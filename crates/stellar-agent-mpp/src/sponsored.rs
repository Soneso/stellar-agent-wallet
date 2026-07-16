//! Sponsored Stellar charge preparation and authorization construction.

use std::fmt;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest as _, Sha256};
use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
use stellar_agent_network::{sep41::build_sep41_transfer_invoke, signing::Signer};
use stellar_agent_sep43::signing::sign_soroban_auth_entry;
use stellar_baselib::{
    account::{Account as BaselibAccount, AccountBehavior},
    transaction::TransactionBehavior,
    transaction_builder::{TransactionBuilder, TransactionBuilderBehavior},
};
use stellar_rpc_client::{Client, SimulateTransactionResponse};
use stellar_strkey::Strkey;
use stellar_xdr::{
    AccountId, ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, HostFunction,
    InvokeContractArgs, InvokeHostFunctionOp, Limits, Memo, Operation, OperationBody,
    Preconditions, PublicKey, ReadXdr, ScAddress, ScBytes, ScMap, ScMapEntry, ScSymbol, ScVal,
    ScVec, SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanCredentials, StringM,
    TimeBounds, TimePoint, TransactionEnvelope, TransactionExt, Uint256, VecM, WriteXdr,
};

use crate::{
    SelectedChallenge,
    credential::{CredentialOutput, build_credential},
    error::{MppError, MppErrorCode},
    limits::{MAX_XDR_BYTES, MIN_CHALLENGE_LIFETIME_SECS},
};

const BASE_FEE_STROOPS: u32 = 100;
const MAX_RESOURCE_FEE_STROOPS: u32 = 10_000_000;
const ESTIMATED_LEDGER_CLOSE_SECONDS: u32 = 5;
const PLACEHOLDER_SOURCE: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

/// RPC boundary used by the sponsored MPP flow.
#[async_trait]
pub trait SponsoredRpc: Send + Sync {
    /// Simulates a transaction envelope without submitting it.
    ///
    /// # Errors
    ///
    /// Returns a bounded, redacted simulation error.
    async fn simulate(
        &self,
        envelope: &TransactionEnvelope,
    ) -> Result<SimulateTransactionResponse, MppError>;
}

/// Production [`SponsoredRpc`] backed by `stellar-rpc-client`.
pub struct StellarSponsoredRpc {
    client: Client,
}

impl StellarSponsoredRpc {
    /// Creates a client for the profile-selected RPC URL.
    ///
    /// # Errors
    ///
    /// Returns `mpp.simulation_failed` when the URL cannot construct a client.
    pub fn new(rpc_url: &str) -> Result<Self, MppError> {
        let client = Client::new(rpc_url).map_err(|_error| simulation_error())?;
        Ok(Self { client })
    }
}

#[async_trait]
impl SponsoredRpc for StellarSponsoredRpc {
    async fn simulate(
        &self,
        envelope: &TransactionEnvelope,
    ) -> Result<SimulateTransactionResponse, MppError> {
        self.client
            .simulate_transaction_envelope(envelope, None)
            .await
            .map_err(|_error| simulation_error())
    }
}

/// Prepared sponsored transaction artifact. It contains no signature and is
/// intentionally redacted from `Debug`.
#[derive(Clone)]
pub struct PreparedSponsoredCharge {
    pub(crate) selected: SelectedChallenge,
    pub(crate) payer: String,
    pub(crate) invoke: InvokeContractArgs,
    pub(crate) auth_entry: SorobanAuthorizationEntry,
    latest_ledger: u32,
    simulated_fee_stroops: u32,
    artifact_hash: [u8; 32],
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub(crate) struct StoredPreparedCharge {
    selected: SelectedChallenge,
    payer: String,
    invoke_xdr: String,
    auth_entry_xdr: String,
    latest_ledger: u32,
    simulated_fee_stroops: u32,
    artifact_hash: [u8; 32],
}

impl PreparedSponsoredCharge {
    /// Returns the validated challenge and charge terms.
    #[must_use]
    pub const fn selected(&self) -> &SelectedChallenge {
        &self.selected
    }

    /// Returns the payer G-strkey.
    #[must_use]
    pub fn payer(&self) -> &str {
        &self.payer
    }

    /// Returns the prepared-artifact SHA-256 digest.
    #[must_use]
    pub const fn artifact_hash(&self) -> &[u8; 32] {
        &self.artifact_hash
    }

    /// Returns the ledger observed during initial simulation.
    #[must_use]
    pub const fn latest_ledger(&self) -> u32 {
        self.latest_ledger
    }

    /// Returns the bounded total simulated transaction fee in stroops.
    #[must_use]
    pub const fn simulated_fee_stroops(&self) -> u32 {
        self.simulated_fee_stroops
    }

    pub(crate) fn to_stored(&self) -> Result<StoredPreparedCharge, MppError> {
        Ok(StoredPreparedCharge {
            selected: self.selected.clone(),
            payer: self.payer.clone(),
            invoke_xdr: self
                .invoke
                .to_xdr_base64(Limits::none())
                .map_err(|_error| simulation_error())?,
            auth_entry_xdr: self
                .auth_entry
                .to_xdr_base64(Limits::none())
                .map_err(|_error| simulation_error())?,
            latest_ledger: self.latest_ledger,
            simulated_fee_stroops: self.simulated_fee_stroops,
            artifact_hash: self.artifact_hash,
        })
    }

    pub(crate) fn from_stored(stored: StoredPreparedCharge) -> Result<Self, MppError> {
        if stored.invoke_xdr.len() > MAX_XDR_BYTES.saturating_mul(2)
            || stored.auth_entry_xdr.len() > MAX_XDR_BYTES.saturating_mul(2)
        {
            return Err(simulation_error());
        }
        stored.selected.context().validate()?;
        // The stored artifact is HMAC-authenticated before it reaches this
        // decode; the workspace bounded-decode convention still applies as
        // defense-in-depth.
        let invoke = InvokeContractArgs::from_xdr_base64(
            &stored.invoke_xdr,
            stellar_agent_xdr_limits::untrusted_decode_limits(stored.invoke_xdr.len()),
        )
        .map_err(|_error| simulation_error())?;
        let auth_entry = SorobanAuthorizationEntry::from_xdr_base64(
            &stored.auth_entry_xdr,
            stellar_agent_xdr_limits::untrusted_decode_limits(stored.auth_entry_xdr.len()),
        )
        .map_err(|_error| simulation_error())?;
        let payer = payer_sc_address(&stored.payer)?;
        validate_auth_entry(&auth_entry, &payer, &invoke)?;
        let expected_hash = prepared_artifact_hash(
            &stored.selected,
            &stored.payer,
            &invoke,
            &auth_entry,
            stored.latest_ledger,
            stored.simulated_fee_stroops,
        )?;
        if expected_hash != stored.artifact_hash {
            return Err(simulation_error());
        }
        Ok(Self {
            selected: stored.selected,
            payer: stored.payer,
            invoke,
            auth_entry,
            latest_ledger: stored.latest_ledger,
            simulated_fee_stroops: stored.simulated_fee_stroops,
            artifact_hash: stored.artifact_hash,
        })
    }
}

impl fmt::Debug for PreparedSponsoredCharge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedSponsoredCharge")
            .field("payer", &redact_strkey(&self.payer))
            .field("latest_ledger", &self.latest_ledger)
            .field("artifact_hash", &hex::encode(self.artifact_hash))
            .field("transaction", &"[redacted]")
            .finish()
    }
}

/// Simulates and validates an unsigned sponsored SEP-41 transfer.
///
/// This function has no signer parameter and therefore cannot request a
/// signature. The caller supplies the already selected payer identity.
///
/// # Errors
///
/// Returns a stable MPP error if the profile is not testnet, the payer or terms
/// are invalid, simulation fails, or simulation does not return exactly the
/// expected single payer authorization entry.
pub async fn prepare_sponsored(
    selected: SelectedChallenge,
    payer: &str,
    network_passphrase: &str,
    rpc: &(dyn SponsoredRpc + Send + Sync),
) -> Result<PreparedSponsoredCharge, MppError> {
    require_testnet(network_passphrase)?;
    let payer_address = payer_sc_address(payer)?;
    let contract = contract_id(selected.request().currency())?;
    let recipient = recipient_sc_address(selected.request().recipient())?;
    let invoke = build_sep41_transfer_invoke(
        contract,
        payer_address.clone(),
        recipient,
        selected.request().amount(),
    )
    .map_err(|_error| simulation_error())?;
    let operation = invoke_operation(invoke.clone(), VecM::default());
    let envelope = build_envelope(
        operation,
        selected.effective_expires_at(),
        BASE_FEE_STROOPS,
        None,
    )?;
    inspect_envelope(
        &envelope,
        &invoke,
        &[],
        selected.effective_expires_at(),
        false,
    )?;

    let response = rpc.simulate(&envelope).await?;
    validate_simulation_response(&response)?;
    let mut results = response.results().map_err(|_error| simulation_error())?;
    if results.len() != 1 {
        return Err(simulation_error());
    }
    let result = results.pop().ok_or_else(simulation_error)?;
    if result.auth.len() != 1 {
        return Err(simulation_error());
    }
    let auth_entry = result
        .auth
        .into_iter()
        .next()
        .ok_or_else(simulation_error)?;
    validate_auth_entry(&auth_entry, &payer_address, &invoke)?;
    let resource_fee =
        u32::try_from(response.min_resource_fee).map_err(|_error| simulation_error())?;
    if resource_fee > MAX_RESOURCE_FEE_STROOPS {
        return Err(simulation_error());
    }
    let simulated_fee_stroops = BASE_FEE_STROOPS
        .checked_add(resource_fee)
        .ok_or_else(simulation_error)?;
    let artifact_hash = prepared_artifact_hash(
        &selected,
        payer,
        &invoke,
        &auth_entry,
        response.latest_ledger,
        simulated_fee_stroops,
    )?;

    Ok(PreparedSponsoredCharge {
        selected,
        payer: payer.to_owned(),
        invoke,
        auth_entry,
        latest_ledger: response.latest_ledger,
        simulated_fee_stroops,
        artifact_hash,
    })
}

/// Signs, re-simulates, locally inspects, and returns the one-shot sponsored
/// MPP credential.
///
/// The prepared artifact is consumed so a single in-process caller cannot
/// accidentally commit it twice. Cross-process replay protection is provided
/// by the authorization store at the service boundary.
///
/// # Errors
///
/// Returns a stable MPP error on expiry, signer mismatch, signing failure,
/// re-simulation failure or mutation, final envelope invariant failure, or
/// credential construction failure.
pub async fn commit_sponsored(
    mut prepared: PreparedSponsoredCharge,
    now_unix: i64,
    network_passphrase: &str,
    signer: &(dyn Signer + Send + Sync),
    rpc: &(dyn SponsoredRpc + Send + Sync),
) -> Result<CredentialOutput, MppError> {
    require_testnet(network_passphrase)?;
    let remaining = prepared
        .selected
        .effective_expires_at()
        .saturating_sub(now_unix);
    if remaining < MIN_CHALLENGE_LIFETIME_SECS {
        return Err(MppError::new(
            MppErrorCode::ChallengeExpired,
            "challenge is expired or too close to expiry",
        ));
    }

    let signer_key = signer
        .public_key()
        .await
        .map_err(|_error| signing_error())?;
    if signer_key.to_string().as_str() != prepared.payer {
        return Err(signing_error());
    }
    let expiration_ledger = compute_expiration_ledger(prepared.latest_ledger, remaining);
    let nonce = match &mut prepared.auth_entry.credentials {
        SorobanCredentials::Address(credentials) => {
            credentials.signature_expiration_ledger = expiration_ledger;
            credentials.nonce
        }
        SorobanCredentials::SourceAccount
        | SorobanCredentials::AddressV2(_)
        | SorobanCredentials::AddressWithDelegates(_) => return Err(simulation_error()),
    };
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(Sha256::digest(network_passphrase.as_bytes()).into()),
        nonce,
        signature_expiration_ledger: expiration_ledger,
        invocation: prepared.auth_entry.root_invocation.clone(),
    });
    let preimage_xdr = preimage
        .to_xdr_base64(Limits::none())
        .map_err(|_error| signing_error())?;
    let signature = sign_soroban_auth_entry(&preimage_xdr, signer, network_passphrase, None)
        .await
        .map_err(|_error| signing_error())?;
    let signature: [u8; 64] = STANDARD
        .decode(signature)
        .map_err(|_error| signing_error())?
        .try_into()
        .map_err(|_bytes: Vec<u8>| signing_error())?;
    let payer_key = match Strkey::from_string(&prepared.payer) {
        Ok(Strkey::PublicKeyEd25519(key)) => key.0,
        _ => return Err(signing_error()),
    };
    let signature_value = account_signature_scval(&payer_key, &signature)?;
    let SorobanCredentials::Address(credentials) = &mut prepared.auth_entry.credentials else {
        return Err(simulation_error());
    };
    credentials.signature = signature_value;
    let signed_entries = vec![prepared.auth_entry.clone()];
    let auth: VecM<SorobanAuthorizationEntry> = signed_entries
        .clone()
        .try_into()
        .map_err(|_error| simulation_error())?;
    let resim_envelope = build_envelope(
        invoke_operation(prepared.invoke.clone(), auth),
        prepared.selected.effective_expires_at(),
        BASE_FEE_STROOPS,
        None,
    )?;
    inspect_envelope(
        &resim_envelope,
        &prepared.invoke,
        &signed_entries,
        prepared.selected.effective_expires_at(),
        false,
    )?;
    let response = rpc.simulate(&resim_envelope).await?;
    validate_simulation_response(&response)?;
    validate_resimulation_auth(&response, &signed_entries)?;
    let resource_fee =
        u32::try_from(response.min_resource_fee).map_err(|_error| simulation_error())?;
    if resource_fee > MAX_RESOURCE_FEE_STROOPS {
        return Err(simulation_error());
    }
    let soroban_data = response
        .transaction_data()
        .map_err(|_error| simulation_error())?;
    let data_size = soroban_data
        .to_xdr(Limits::none())
        .map_err(|_error| simulation_error())?
        .len();
    if data_size > MAX_XDR_BYTES {
        return Err(simulation_error());
    }
    let final_auth: VecM<SorobanAuthorizationEntry> = signed_entries
        .clone()
        .try_into()
        .map_err(|_error| simulation_error())?;
    let final_envelope = build_envelope(
        invoke_operation(prepared.invoke.clone(), final_auth),
        prepared.selected.effective_expires_at(),
        BASE_FEE_STROOPS.saturating_add(resource_fee),
        Some(soroban_data),
    )?;
    inspect_envelope(
        &final_envelope,
        &prepared.invoke,
        &signed_entries,
        prepared.selected.effective_expires_at(),
        true,
    )?;
    let transaction_xdr = final_envelope
        .to_xdr_base64(Limits::none())
        .map_err(|_error| simulation_error())?;
    build_credential(&prepared.selected, &prepared.payer, &transaction_xdr)
}

fn build_envelope(
    operation: Operation,
    expires_at: i64,
    fee: u32,
    soroban_data: Option<stellar_xdr::SorobanTransactionData>,
) -> Result<TransactionEnvelope, MppError> {
    let max_time = u64::try_from(expires_at).map_err(|_error| simulation_error())?;
    let mut source = placeholder_source_account()?;
    let mut builder = TransactionBuilder::new(
        &mut source,
        TESTNET_PASSPHRASE,
        Some(TimeBounds {
            min_time: TimePoint(0),
            max_time: TimePoint(max_time),
        }),
    );
    builder.fee(fee).add_operation(operation);
    let mut transaction = builder.build_for_simulation();
    transaction.soroban_data = soroban_data;
    transaction
        .to_envelope()
        .map_err(|_error| simulation_error())
}

fn invoke_operation(
    invoke: InvokeContractArgs,
    auth: VecM<SorobanAuthorizationEntry>,
) -> Operation {
    Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(invoke),
            auth,
        }),
    }
}

fn validate_simulation_response(response: &SimulateTransactionResponse) -> Result<(), MppError> {
    if response.error.is_some()
        || response.min_resource_fee == 0
        || response.transaction_data.is_empty()
        || response.transaction_data.len() > MAX_XDR_BYTES.saturating_mul(2)
        || response.results.len() != 1
        || response.results.iter().any(|result| {
            result.xdr.len() > MAX_XDR_BYTES.saturating_mul(2)
                || result
                    .auth
                    .iter()
                    .any(|entry| entry.len() > MAX_XDR_BYTES.saturating_mul(2))
        })
    {
        return Err(simulation_error());
    }
    Ok(())
}

fn validate_resimulation_auth(
    response: &SimulateTransactionResponse,
    expected: &[SorobanAuthorizationEntry],
) -> Result<(), MppError> {
    let results = response.results().map_err(|_error| simulation_error())?;
    let Some(result) = results.first() else {
        return Err(simulation_error());
    };
    if !result.auth.is_empty() && result.auth.as_slice() != expected {
        return Err(simulation_error());
    }
    Ok(())
}

fn validate_auth_entry(
    entry: &SorobanAuthorizationEntry,
    payer: &ScAddress,
    invoke: &InvokeContractArgs,
) -> Result<(), MppError> {
    let SorobanCredentials::Address(credentials) = &entry.credentials else {
        return Err(simulation_error());
    };
    if &credentials.address != payer
        || credentials.signature_expiration_ledger != 0
        || !matches!(credentials.signature, ScVal::Void)
        || !entry.root_invocation.sub_invocations.is_empty()
        || entry.root_invocation.function != SorobanAuthorizedFunction::ContractFn(invoke.clone())
    {
        return Err(simulation_error());
    }
    Ok(())
}

fn inspect_envelope(
    envelope: &TransactionEnvelope,
    invoke: &InvokeContractArgs,
    auth: &[SorobanAuthorizationEntry],
    expires_at: i64,
    require_soroban_data: bool,
) -> Result<(), MppError> {
    let TransactionEnvelope::Tx(value) = envelope else {
        return Err(simulation_error());
    };
    let expected_source = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([0; 32])));
    let expected_max = u64::try_from(expires_at).map_err(|_error| simulation_error())?;
    let time_bounds = match &value.tx.cond {
        Preconditions::Time(bounds) => Some(bounds),
        Preconditions::V2(value) => value.time_bounds.as_ref(),
        Preconditions::None => None,
    };
    let Some(time_bounds) = time_bounds else {
        return Err(simulation_error());
    };
    if value.tx.source_account.clone().account_id() != expected_source
        || value.tx.seq_num.0 != 1
        || !value.signatures.is_empty()
        || !matches!(value.tx.memo, Memo::None)
        || time_bounds.min_time.0 != 0
        || time_bounds.max_time.0 != expected_max
        || value.tx.operations.len() != 1
        || require_soroban_data != matches!(value.tx.ext, TransactionExt::V1(_))
    {
        return Err(simulation_error());
    }
    let operation = value.tx.operations.first().ok_or_else(simulation_error)?;
    let OperationBody::InvokeHostFunction(host) = &operation.body else {
        return Err(simulation_error());
    };
    if operation.source_account.is_some()
        || host.host_function != HostFunction::InvokeContract(invoke.clone())
        || host.auth.as_slice() != auth
    {
        return Err(simulation_error());
    }
    Ok(())
}

fn prepared_artifact_hash(
    selected: &SelectedChallenge,
    payer: &str,
    invoke: &InvokeContractArgs,
    auth: &SorobanAuthorizationEntry,
    latest_ledger: u32,
    simulated_fee_stroops: u32,
) -> Result<[u8; 32], MppError> {
    let mut hash = Sha256::new();
    hash.update(b"stellar-agent-mpp-prepared:v1\0");
    update_length_prefixed(&mut hash, selected.challenge_digest());
    update_length_prefixed(&mut hash, payer.as_bytes());
    update_length_prefixed(
        &mut hash,
        &invoke
            .to_xdr(Limits::none())
            .map_err(|_error| simulation_error())?,
    );
    update_length_prefixed(
        &mut hash,
        &auth
            .to_xdr(Limits::none())
            .map_err(|_error| simulation_error())?,
    );
    update_length_prefixed(&mut hash, &latest_ledger.to_be_bytes());
    update_length_prefixed(&mut hash, &simulated_fee_stroops.to_be_bytes());
    Ok(hash.finalize().into())
}

fn update_length_prefixed(hash: &mut Sha256, value: &[u8]) {
    hash.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(value);
}

fn account_signature_scval(key: &[u8; 32], signature: &[u8; 64]) -> Result<ScVal, MppError> {
    let public_key = ScMapEntry {
        key: symbol("public_key")?,
        val: ScVal::Bytes(ScBytes(
            key.to_vec().try_into().map_err(|_error| signing_error())?,
        )),
    };
    let signature = ScMapEntry {
        key: symbol("signature")?,
        val: ScVal::Bytes(ScBytes(
            signature
                .to_vec()
                .try_into()
                .map_err(|_error| signing_error())?,
        )),
    };
    let map = ScMap(
        vec![public_key, signature]
            .try_into()
            .map_err(|_error| signing_error())?,
    );
    let vector = ScVec(
        vec![ScVal::Map(Some(map))]
            .try_into()
            .map_err(|_error| signing_error())?,
    );
    Ok(ScVal::Vec(Some(vector)))
}

fn symbol(value: &str) -> Result<ScVal, MppError> {
    let string: StringM<32> = value.try_into().map_err(|_error| signing_error())?;
    Ok(ScVal::Symbol(ScSymbol(string)))
}

fn placeholder_source_account() -> Result<BaselibAccount, MppError> {
    BaselibAccount::new(PLACEHOLDER_SOURCE, "0").map_err(|_error| simulation_error())
}

fn contract_id(value: &str) -> Result<ContractId, MppError> {
    match Strkey::from_string(value) {
        Ok(Strkey::Contract(contract)) => Ok(ContractId(Hash(contract.0))),
        _ => Err(simulation_error()),
    }
}

fn payer_sc_address(value: &str) -> Result<ScAddress, MppError> {
    match Strkey::from_string(value) {
        Ok(Strkey::PublicKeyEd25519(key)) => Ok(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256(key.0)),
        ))),
        _ => Err(MppError::new(
            MppErrorCode::ChallengeInvalid,
            "MPP payer must be a classic account",
        )),
    }
}

fn recipient_sc_address(value: &str) -> Result<ScAddress, MppError> {
    match Strkey::from_string(value) {
        Ok(Strkey::PublicKeyEd25519(key)) => Ok(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256(key.0)),
        ))),
        Ok(Strkey::Contract(contract)) => Ok(ScAddress::Contract(ContractId(Hash(contract.0)))),
        _ => Err(simulation_error()),
    }
}

// Rounds DOWN so the signed authorization entry expires no later than the
// challenge under the nominal ledger close time — the entry expiry is the
// only wallet-imposed bound once the server rebuilds the outer transaction.
// The minimum of one ledger keeps a usable window; the 30-second minimum
// challenge lifetime guarantees at least six nominal ledgers remain.
fn compute_expiration_ledger(latest_ledger: u32, remaining_seconds: i64) -> u32 {
    let seconds = u64::try_from(remaining_seconds).unwrap_or(0);
    let ledgers = (seconds / u64::from(ESTIMATED_LEDGER_CLOSE_SECONDS)).max(1);
    latest_ledger.saturating_add(u32::try_from(ledgers).unwrap_or(u32::MAX))
}

fn require_testnet(passphrase: &str) -> Result<(), MppError> {
    if passphrase != TESTNET_PASSPHRASE {
        return Err(MppError::new(
            MppErrorCode::NetworkForbidden,
            "MPP charge is enabled only on Stellar testnet",
        ));
    }
    Ok(())
}

fn redact_strkey(value: &str) -> String {
    if value.len() <= 10 {
        return "[redacted]".to_owned();
    }
    format!("{}...{}", &value[..5], &value[value.len() - 5..])
}

const fn simulation_error() -> MppError {
    MppError::new(
        MppErrorCode::SimulationFailed,
        "sponsored transaction simulation failed validation",
    )
}

const fn signing_error() -> MppError {
    MppError::new(
        MppErrorCode::SigningFailed,
        "sponsored authorization signing failed",
    )
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        reason = "test fixtures use expect and panic for concise assertions"
    )]

    use std::sync::atomic::{AtomicUsize, Ordering};

    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use stellar_agent_network::signing::{Signer as _, SoftwareSigningKey};
    use stellar_xdr::{SorobanAddressCredentials, SorobanAuthorizedInvocation, WriteXdr as _};

    use super::*;
    use crate::{ChallengeInput, HttpRequestContext, select_and_validate};

    const CONTRACT: &str = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
    const RECIPIENT: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    const TRANSACTION_DATA: &str = "AAAAAAAAAAIAAAAGAAAAAcwD/nT9D7Dc2LxRdab+2vEUF8B+XoN7mQW21oxPT8ALAAAAFAAAAAEAAAAHy8vNUZ8vyZ2ybPHW0XbSrRtP7gEWsJ6zDzcfY9P8z88AAAABAAAABgAAAAHMA/50/Q+w3Ni8UXWm/trxFBfAfl6De5kFttaMT0/ACwAAABAAAAABAAAAAgAAAA8AAAAHQ291bnRlcgAAAAASAAAAAAAAAAAg4dbAxsGAGICfBG3iT2cKGYQ6hK4sJWzZ6or1C5v6GAAAAAEAHfKyAAAFiAAAAIgAAAAAAAAAAw==";

    pub(crate) struct DeterministicRpc {
        calls: AtomicUsize,
        payer: ScAddress,
    }

    impl DeterministicRpc {
        pub(crate) fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl SponsoredRpc for DeterministicRpc {
        async fn simulate(
            &self,
            envelope: &TransactionEnvelope,
        ) -> Result<SimulateTransactionResponse, MppError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let TransactionEnvelope::Tx(transaction) = envelope else {
                return Err(simulation_error());
            };
            let operation = transaction
                .tx
                .operations
                .first()
                .ok_or_else(simulation_error)?;
            let OperationBody::InvokeHostFunction(host) = &operation.body else {
                return Err(simulation_error());
            };
            let HostFunction::InvokeContract(invoke) = &host.host_function else {
                return Err(simulation_error());
            };
            let auth = if host.auth.is_empty() {
                let entry = SorobanAuthorizationEntry {
                    credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                        address: self.payer.clone(),
                        nonce: 7,
                        signature_expiration_ledger: 0,
                        signature: ScVal::Void,
                    }),
                    root_invocation: SorobanAuthorizedInvocation {
                        function: SorobanAuthorizedFunction::ContractFn(invoke.clone()),
                        sub_invocations: VecM::default(),
                    },
                };
                vec![
                    entry
                        .to_xdr_base64(Limits::none())
                        .map_err(|_| simulation_error())?,
                ]
            } else {
                Vec::new()
            };
            serde_json::from_value(serde_json::json!({
                "transactionData": TRANSACTION_DATA,
                "minResourceFee": "1000",
                "results": [{
                    "auth": auth,
                    "xdr": ScVal::Void.to_xdr_base64(Limits::none()).map_err(|_| simulation_error())?
                }],
                "latestLedger": 1000
            }))
            .map_err(|_| simulation_error())
        }
    }

    pub(crate) fn selected_challenge(now: i64) -> SelectedChallenge {
        selected_challenge_for_resource(now, "https://merchant.example/checkout")
    }

    pub(crate) fn selected_challenge_for_resource(now: i64, resource: &str) -> SelectedChallenge {
        let request = serde_json::json!({
            "amount": "10000000",
            "currency": CONTRACT,
            "methodDetails": {"feePayer": true, "network": "stellar:testnet"},
            "recipient": RECIPIENT
        });
        let encoded = URL_SAFE_NO_PAD
            .encode(crate::json::canonical_json(&request).expect("canonical challenge request"));
        let context =
            HttpRequestContext::new("https://merchant.example", "POST", resource, None, None)
                .expect("valid request context");
        select_and_validate(
            &ChallengeInput::Http {
                www_authenticate: vec![format!(
                    "Payment id=\"challenge-1\", realm=\"merchant.example\", method=\"stellar\", intent=\"charge\", request={encoded}"
                )],
                selected_challenge_id: None,
                context,
            },
            now,
        )
        .expect("valid selected challenge")
    }

    pub(crate) async fn prepared_fixture(
        now: i64,
    ) -> (
        PreparedSponsoredCharge,
        SoftwareSigningKey,
        DeterministicRpc,
    ) {
        prepared_fixture_for_resource(now, "https://merchant.example/checkout").await
    }

    pub(crate) async fn prepared_fixture_for_resource(
        now: i64,
        resource: &str,
    ) -> (
        PreparedSponsoredCharge,
        SoftwareSigningKey,
        DeterministicRpc,
    ) {
        let signer = SoftwareSigningKey::new_from_bytes([1; 32]);
        let payer = signer.public_key().await.expect("public key").to_string();
        let rpc = DeterministicRpc {
            calls: AtomicUsize::new(0),
            payer: payer_sc_address(&payer).expect("payer"),
        };
        let prepared = prepare_sponsored(
            selected_challenge_for_resource(now, resource),
            &payer,
            TESTNET_PASSPHRASE,
            &rpc,
        )
        .await
        .expect("prepare fixture");
        (prepared, signer, rpc)
    }

    #[test]
    fn expiration_floors_to_the_challenge_window_and_saturates() {
        assert_eq!(compute_expiration_ledger(100, 1), 101);
        assert_eq!(compute_expiration_ledger(100, 6), 101);
        assert_eq!(compute_expiration_ledger(100, 300), 160);
        assert_eq!(compute_expiration_ledger(u32::MAX - 1, 300), u32::MAX);
    }

    #[test]
    fn mainnet_is_refused_structurally() {
        let error = require_testnet("Public Global Stellar Network ; September 2015")
            .expect_err("mainnet must fail");
        assert_eq!(error.code(), "mpp.network_forbidden");
    }

    #[test]
    fn signature_value_has_expected_shape() {
        let value = account_signature_scval(&[1; 32], &[2; 64]).expect("fixed shape");
        let ScVal::Vec(Some(values)) = value else {
            panic!("expected vector")
        };
        assert_eq!(values.0.len(), 1);
    }

    #[tokio::test]
    async fn mainnet_refusal_makes_zero_rpc_calls() {
        let rpc = DeterministicRpc {
            calls: AtomicUsize::new(0),
            payer: payer_sc_address(RECIPIENT).expect("payer"),
        };
        let error = prepare_sponsored(
            selected_challenge(1_700_000_000),
            RECIPIENT,
            "Public Global Stellar Network ; September 2015",
            &rpc,
        )
        .await
        .expect_err("mainnet must be refused");
        assert_eq!(error.code(), "mpp.network_forbidden");
        assert_eq!(rpc.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn sponsored_prepare_and_commit_builds_one_shot_credential() {
        let (prepared, signer, rpc) = prepared_fixture(1_700_000_000).await;
        let payer = signer.public_key().await.expect("public key").to_string();
        assert_eq!(rpc.calls.load(Ordering::SeqCst), 1);
        assert_eq!(prepared.simulated_fee_stroops(), 1_100);

        let credential =
            commit_sponsored(prepared, 1_700_000_001, TESTNET_PASSPHRASE, &signer, &rpc)
                .await
                .expect("commit");
        assert_eq!(rpc.calls.load(Ordering::SeqCst), 2);
        let CredentialOutput::Http { authorization } = credential else {
            panic!("HTTP challenge must produce HTTP credential")
        };
        let encoded: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(authorization.strip_prefix("Payment ").expect("scheme"))
                .expect("base64url credential"),
        )
        .expect("credential JSON");
        let transaction = encoded["payload"]["transaction"]
            .as_str()
            .expect("transaction credential");
        assert!(STANDARD.decode(transaction).is_ok());
        assert_eq!(
            encoded["source"],
            format!("did:pkh:stellar:testnet:{payer}")
        );
    }
}
