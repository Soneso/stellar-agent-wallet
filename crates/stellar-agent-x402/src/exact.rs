//! Exact Stellar scheme orchestrator: constructs a signed SAC `transfer`
//! payment payload compatible with the x402 v2 `PAYMENT-SIGNATURE` wire format.
//!
//! # Flow
//!
//! ```text
//! 1. Validate requirements (validate_requirements)
//! 2. Endpoint identity: getNetwork on the caller's client, the first request
//! 3. Build SAC transfer InvokeHostFunction
//! 4. simulateTransaction: restoration, fee bounds, transaction data, exactly
//!    one result, and the payer authorization against the built transfer;
//!    harvest the nonce and latest_ledger; compute signature_expiration_ledger
//!    (window of 1 to 60 ledgers)
//! 5. Cross-check witness: when the caller's prepared cross-check requires it,
//!    the oracle simulates the same unsigned envelope and the answers are
//!    compared; getHealth on the caller's client; ledger consistency
//! 6. Set expiration on auth entry; sign via sep43 (single auth-signing call site)
//! 7. Transmit gate: the caller's `before_transmit` runs; an error stops here
//! 8. Re-simulate with signed auth (mandatory footprint refresh): restoration,
//!    fee bounds, transaction data, no authorization other than the signed
//!    entry, ledger consistency
//! 9. Build + serialize final TransactionEnvelope to base64 XDR
//! 10. Wrap in PaymentPayload; return it with the cross-check outcome
//! ```
//!
//! The flow matches the @x402/stellar reference implementation. Auth-entry
//! signing goes through a single call site
//! (`stellar_agent_sep43::sign_soroban_auth_entry`). The re-simulation in step 8
//! is the first time the signed authorization leaves the wallet, to the
//! configured RPC. The transmit gate in step 7 is the last point at which the
//! caller can withhold it.
//!
//! Every request of the payment goes to the client the caller passes, and the
//! endpoint identity check is its first request. The simulation answers come
//! from that endpoint. Nothing is signed unless the first answer holds exactly
//! one unsigned payer authorization for the transfer built in step 3, with no
//! nested calls. The nonce, the `latest_ledger`, the resource data, and the fee
//! come from that endpoint.
//!
//! When the payment's value requires the cross-check witness, the caller's
//! prepared [`SorobanCrossCheck`] holds an oracle client built from the
//! operator's profile, and the crate builds none itself. The oracle simulates
//! the same unsigned envelope before anything is signed. Its answer must hold
//! the same authorization entries apart from the nonce and the expiration, a
//! resource fee within the ceiling, and a ledger no more than two behind the
//! primary's and before the signature expiration. That is independent evidence
//! that the transfer simulates and that the ledger the expiration derives from
//! is current. The oracle's answer is never signed and never replaces the
//! primary's; the payload carries the primary's nonce and resource data.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use sha2::{Digest as _, Sha256};
use stellar_baselib::account::{Account as BaselibAccount, AccountBehavior};
use stellar_baselib::transaction::TransactionBehavior;
use stellar_baselib::transaction_builder::{TransactionBuilder, TransactionBuilderBehavior};
use stellar_rpc_client::SimulateTransactionResponse;
use stellar_strkey::Strkey;
use stellar_xdr::{
    Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, HostFunction, InvokeContractArgs,
    InvokeHostFunctionOp, Limits, Operation, OperationBody, ScAddress, ScBytes, ScMap, ScMapEntry,
    ScSymbol, ScVal, ScVec, SorobanAddressCredentials, SorobanAuthorizationEntry,
    SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials,
    SorobanTransactionData, SorobanTransactionDataExt, StringM, VecM, WriteXdr,
};
use tokio::time::Instant;

use stellar_agent_core::error::MAINNET_SIGNING_REFUSAL_DETAIL;
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::cross_check::{
    CrossCheckOutcome, CrossCheckWitness, SorobanCrossCheck, SorobanWitnessInputs,
};
use stellar_agent_network::quote_server_text;
use stellar_agent_network::refuse_mainnet_write;
use stellar_agent_network::signing::Signer;
use stellar_agent_sep43::signing::sign_soroban_auth_entry;

use crate::X402Error;
use crate::constants::x402_network_to_passphrase;
use crate::sac_transfer::{build_sac_transfer_invoke, strkey_to_recipient_sc_address};
use crate::wire::{ExactStellarPayloadV2, PaymentPayload, PaymentRequirements};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Base transaction fee in stroops used for simulate and re-simulate builds.
///
/// The resource fee from the re-simulation is added on top.
const BASE_FEE_STROOPS: u32 = 100;

/// Estimated ledger close time in seconds for x402 expiration calculation.
///
/// The @x402/stellar reference implementation samples recent Horizon ledgers
/// and averages the inter-close intervals, falling back to `5` seconds on
/// error. The wallet uses the documented fallback constant.
const ESTIMATED_LEDGER_CLOSE_SECONDS: u32 = 5;

/// Longest validity, in seconds, the wallet signs a payment authorization for.
///
/// `maxTimeoutSeconds` names a maximum, so a shorter signed validity meets it.
/// A larger value is clamped to this one, which bounds the signature window
/// at 60 ledgers.
const MAX_SIGNED_VALIDITY_SECONDS: u32 = 300;

/// Ceiling, in stroops, on the resource fee a simulation answer may report.
///
/// A local sanity bound on the values that enter the payment transaction,
/// separate from any fee policy of the facilitator that settles it. The payer
/// signs no transaction fee. The value matches the MPP sponsored-charge
/// ceiling.
const MAX_RESOURCE_FEE_STROOPS: u32 = 10_000_000;

// The final fee is `BASE_FEE_STROOPS` plus a resource fee no larger than the
// ceiling, so the sum fits the `u32` fee field.
const _: () = assert!(
    MAX_RESOURCE_FEE_STROOPS
        .checked_add(BASE_FEE_STROOPS)
        .is_some()
);

/// `getHealth` status of an endpoint that serves current ledgers.
const HEALTHY_STATUS: &str = "healthy";

/// Placeholder transaction source account used while constructing the payment.
///
/// The payer authorizes via the signed `Address` auth entry, not via the
/// transaction's source-account signature. Building with a source distinct from
/// the payer is what makes the payer's `transfer(from, ..)` authorization
/// surface as a signable `Address` auth entry instead of collapsing into a
/// `SourceAccount` credential. The facilitator that settles the payment rebuilds
/// the transaction with its own account as the source before submitting, so this
/// placeholder and its sequence number are never used on-chain. The all-zero
/// ed25519 account is never a real payer.
const PLACEHOLDER_SOURCE: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

// ─────────────────────────────────────────────────────────────────────────────
// Transmit gate
// ─────────────────────────────────────────────────────────────────────────────

/// The signed authorization [`create_payment`] is about to transmit, as its
/// transmit gate sees it.
///
/// Every field describes the payload that leaves the wallet in the signed
/// re-simulation. A caller records it durably before returning `Ok` from the
/// gate. The struct carries no signature bytes and no key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthorizationToTransmit<'a> {
    /// x402 wire network of the signed authorization. Always `stellar:testnet`:
    /// [`validate_requirements`] refuses `stellar:pubnet` before anything is
    /// signed.
    pub network: &'a str,
    /// x402 scheme of the signed authorization; always `exact`.
    pub scheme: &'a str,
    /// Payer G-strkey whose key signed the authorization.
    pub payer: &'a str,
    /// Recipient address the SAC `transfer` pays.
    pub pay_to: &'a str,
    /// SAC contract C-strkey of the transferred asset.
    pub asset: &'a str,
    /// Transferred amount in the asset's atomic units.
    pub amount: i128,
    /// Ledger after which the signed authorization stops being valid.
    pub signature_expiration_ledger: u32,
    /// The cross-check witness obtained before signing, when the payment's
    /// value required one.
    pub cross_check: Option<&'a CrossCheckWitness>,
}

/// A signed payment and the cross-check outcome of its construction.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CreatedPayment {
    /// The signed x402 payment payload.
    pub payload: PaymentPayload,
    /// The cross-check outcome: passed with the oracle's witness, skipped,
    /// or not required.
    pub cross_check: CrossCheckOutcome,
}

// ─────────────────────────────────────────────────────────────────────────────
// validate_requirements
// ─────────────────────────────────────────────────────────────────────────────

/// Checks `requirements` against the wallet's local rules and returns the
/// transfer amount in atomic units.
///
/// The check sends no request and touches no key, so a host can run it before
/// it admits the payment against a spending window. [`create_payment`] runs it
/// again on the requirements it receives.
///
/// The checks run in this order:
///
/// 1. `scheme` is `exact`.
/// 2. `network` is `stellar:testnet` or `stellar:pubnet`, and its passphrase
///    equals `profile_passphrase`.
/// 3. Neither the passphrase nor `rpc_url` is mainnet.
/// 4. `asset` is a C-strkey.
/// 5. `extra.areFeesSponsored` is the JSON boolean `true`.
/// 6. `amount` is an integer string above zero that fits `i128`.
/// 7. `payTo` is a G-, C-, or M-strkey.
/// 8. `maxTimeoutSeconds` is at least one. A value above 300 is accepted, and
///    [`create_payment`] signs a validity of 300 seconds for it.
///
/// A C-strkey `asset` is a contract address; the check does not establish
/// that the contract is a Stellar Asset Contract.
///
/// # Errors
///
/// - [`X402Error::UnsupportedScheme`]: `scheme` is not `"exact"`.
/// - [`X402Error::UnsupportedNetwork`]: `network` is not in
///   `{stellar:pubnet, stellar:testnet}`.
/// - [`X402Error::NetworkPassphraseMismatch`]: the network's passphrase is
///   not `profile_passphrase`.
/// - [`X402Error::MainnetSigningForbidden`]: the passphrase is mainnet, or
///   `rpc_url` matches a mainnet host pattern.
/// - [`X402Error::InvalidAssetAddress`]: `asset` is not a valid C-strkey.
/// - [`X402Error::FeesNotSponsored`]: `extra.areFeesSponsored` is not `true`.
/// - [`X402Error::AmountConversion`]: `amount` is not a positive `i128`.
/// - [`X402Error::InvalidRecipientAddress`]: `payTo` is not a G-, C-, or
///   M-strkey.
/// - [`X402Error::InvalidPaymentRequired`]: `maxTimeoutSeconds` is zero.
///
/// # Examples
///
/// ```
/// use stellar_agent_x402::exact::validate_requirements;
/// use stellar_agent_x402::wire::PaymentRequirements;
///
/// let requirements = PaymentRequirements {
///     scheme: "exact".to_owned(),
///     network: "stellar:testnet".to_owned(),
///     asset: "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC".to_owned(),
///     amount: "1000000".to_owned(),
///     pay_to: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF".to_owned(),
///     max_timeout_seconds: 300,
///     extra: serde_json::json!({ "areFeesSponsored": true }),
/// };
/// let amount = validate_requirements(
///     &requirements,
///     "Test SDF Network ; September 2015",
///     "https://soroban-testnet.stellar.org",
/// )
/// .unwrap();
/// assert_eq!(amount, 1_000_000);
/// ```
pub fn validate_requirements(
    requirements: &PaymentRequirements,
    profile_passphrase: &str,
    rpc_url: &str,
) -> Result<i128, X402Error> {
    if requirements.scheme != "exact" {
        return Err(X402Error::UnsupportedScheme {
            scheme: quote_server_text(&requirements.scheme),
        });
    }

    // The x402 wire says "stellar:pubnet" where the wallet's CAIP-2 says
    // "stellar:mainnet"; the passphrase is the common ground.
    let network_passphrase = x402_network_to_passphrase(&requirements.network)?;
    if network_passphrase != profile_passphrase {
        return Err(X402Error::NetworkPassphraseMismatch {
            network: requirements.network.clone(),
            expected_passphrase: network_passphrase,
            profile_passphrase: profile_passphrase.to_owned(),
        });
    }

    // A mainnet passphrase or a mainnet-pattern endpoint never reaches the
    // signer or the endpoint.
    refuse_mainnet_write(network_passphrase, rpc_url).map_err(|_| {
        X402Error::MainnetSigningForbidden {
            detail: MAINNET_SIGNING_REFUSAL_DETAIL.to_owned(),
        }
    })?;

    validate_c_strkey(&requirements.asset)?;

    // The reference implementation tests `extra.areFeesSponsored` for
    // JavaScript truthiness, which accepts `"true"`, `1`, or any non-null
    // value. The wallet requires the JSON boolean `true` and refuses the
    // ambiguous encodings.
    if requirements.extra.get("areFeesSponsored") != Some(&serde_json::Value::Bool(true)) {
        return Err(X402Error::FeesNotSponsored);
    }

    // The wire amount is already in atomic units; no decimals are applied.
    let amount: i128 =
        requirements
            .amount
            .parse::<i128>()
            .map_err(|e| X402Error::AmountConversion {
                detail: format!(
                    "wire amount {} is not a valid i128: {e}",
                    quote_server_text(&requirements.amount)
                ),
            })?;
    if amount <= 0 {
        return Err(X402Error::AmountConversion {
            detail: format!(
                "wire amount must be a positive integer (> 0), got {}",
                requirements.amount
            ),
        });
    }

    strkey_to_recipient_sc_address(&requirements.pay_to)?;

    if requirements.max_timeout_seconds == 0 {
        return Err(X402Error::InvalidPaymentRequired {
            detail: "maxTimeoutSeconds must be at least 1".to_owned(),
        });
    }

    Ok(amount)
}

// ─────────────────────────────────────────────────────────────────────────────
// create_payment
// ─────────────────────────────────────────────────────────────────────────────

/// Constructs a signed x402 v2 [`PaymentPayload`] for the Exact Stellar scheme.
///
/// Implements the step flow below, wire-compatible with the @x402/stellar
/// reference implementation.
///
/// Every request of the payment goes to `client`, and every request of the
/// cross-check witness goes to the oracle client `cross_check` holds. A caller
/// builds both for this payment from the operator's profile, never from the
/// payment-required body; the crate builds no client. The first request on
/// `client` is the endpoint identity check, so a client whose endpoint serves
/// another network, or whose identity cannot be established before
/// `identity_deadline`, sends nothing else.
///
/// A mainnet network passphrase or a mainnet-pattern `client.url()` is refused
/// with [`X402Error::MainnetSigningForbidden`] before any signing call and any
/// request. An endpoint that reports the mainnet passphrase is refused by the
/// identity check, before any simulation.
///
/// The signed authorization first leaves the wallet in the re-simulation of
/// step 8. `before_transmit` runs once, immediately before that request, and
/// only after the signature exists. An error from it returns at once: nothing
/// is sent, and the error is returned unchanged. A caller that must record the
/// authorization before it leaves the wallet does so inside `before_transmit`.
///
/// # Steps
///
/// 1. [`validate_requirements`] with `profile_passphrase` and `client.url()`.
/// 2. [`StellarRpcClient::endpoint_identity`] under `identity_deadline`.
/// 3. Build a SAC `transfer` `InvokeHostFunction`.
/// 4. `simulateTransaction`. The answer carries no error and no restore
///    preamble. Its `min_resource_fee` lies in `1..=10_000_000` stroops, and
///    its transaction data decodes, lists no archived entries to restore, and
///    embeds a resource fee in `0..=min_resource_fee`. It holds exactly one
///    result, and that result holds exactly one authorization entry, with
///    legacy `Address` credentials for the payer. The entry carries a zero
///    `signature_expiration_ledger`, a `Void` signature, and a root invocation
///    equal to the step 3 transfer with no nested calls. Compute
///    `signature_expiration_ledger` as `L + ceil(min(t, 300) / 5)`, with `L`
///    the answer's `latest_ledger` and `t` the requirement's
///    `maxTimeoutSeconds`; an overflow refuses.
/// 5. Obtain the cross-check witness through `cross_check`: when it requires
///    a witness, the oracle simulates the step 4 envelope and its answer is
///    compared with the first answer. Then read `getHealth` on `client` under
///    `identity_deadline`. The status is `healthy`, `L` is above zero, `L` is
///    at most one ledger ahead of the health ledger `H`, and `H` lies before
///    the expiration ledger.
/// 6. Set `signature_expiration_ledger` on the payer's credentials and sign
///    the built `transfer` invocation via
///    `stellar_agent_sep43::sign_soroban_auth_entry` (the single auth-signing
///    call site).
/// 7. Call `before_transmit` with the [`AuthorizationToTransmit`]; return its
///    error unchanged.
/// 8. Re-simulate with the signed auth entry (MANDATORY). Without this,
///    submit traps with "trying to access contract data key outside of the
///    footprint". The answer passes the step 4 checks on errors,
///    restoration, fees, and transaction data. Its first result decodes, and
///    its authorization entries are empty or equal to the signed entries. Its
///    `latest_ledger` `R` is at most one ledger behind `H` and lies before the
///    expiration ledger.
/// 9. Build the final `TransactionEnvelope` with the re-simulation's
///    transaction data and a fee of 100 stroops plus its `min_resource_fee`,
///    and serialize it to base64 XDR.
/// 10. Wrap in a [`PaymentPayload`] and return it with the cross-check
///     outcome as a [`CreatedPayment`].
///
/// The step 4 check accepts the answer of an honest recording simulation for a
/// G-account payer distinct from the placeholder source. That answer holds one
/// legacy `Address` entry that records the original `transfer` arguments, a
/// muxed recipient included. The step 8 check accepts the empty or unchanged
/// entries of an honest enforcing simulation.
///
/// The ledger checks of steps 5 and 8 compare answers of `client`'s endpoint
/// with each other. They tolerate one ledger of skew between load-balanced
/// backends and bound the signed window at 60 ledger advances plus that skew.
/// The cross-check witness of step 5 compares the first answer's ledger with
/// the oracle's, which establishes that it is current when a witness is
/// required.
///
/// The health read keeps the absolute `identity_deadline`, so a witness that
/// runs past it refuses at the health read, before anything is signed.
///
/// The wallet has no restore path. An answer that asks for a restoration, by a
/// restore preamble or by archived entries in its transaction data, refuses.
/// A restoration made elsewhere unblocks the payment.
///
/// A failure after `before_transmit` returned `Ok` follows the signed
/// authorization's send, so the caller cannot withdraw that authorization.
///
/// # Arguments
///
/// - `requirements`: payment requirements from the 402 header.
/// - `signer`: signer implementation providing the payer's key.
/// - `client`: the Stellar RPC client for this payment, built from the
///   operator's profile and never from the payment-required body.
/// - `cross_check`: the prepared [`SorobanCrossCheck`] for this payment's
///   value; it holds the oracle client when a witness is required.
/// - `profile_passphrase`: the network passphrase from the operator's profile,
///   checked against `requirements.network` and against the endpoint.
/// - `identity_deadline`: the absolute deadline of the endpoint identity check
///   and of the health read. A caller derives it from its own timeout, never
///   from `maxTimeoutSeconds`.
/// - `before_transmit`: the transmit gate of step 7. A gate that refuses
///   returns [`X402Error::TransmitGateRefused`] or any other variant.
///
/// # Errors
///
/// - Every error of [`validate_requirements`].
/// - [`X402Error::EndpointIdentity`]: the endpoint identity check refused. The
///   wire code is the check's own `network.*` code.
/// - [`X402Error::CrossCheck`]: the cross-check witness refused before
///   anything was signed: `simulation.divergence`,
///   `network.witness_unavailable`, or `network.rpc_credential_refused`.
/// - [`X402Error::RpcSimulateFailed`]: a simulation request or answer failed
///   a check of step 4, 5, or 8 other than the authorization checks, or the
///   first answer held no result or more than one. The variant also covers a
///   failed health read, a status other than `healthy`, and a signer public
///   key that could not be read. A failed request's detail carries the
///   scrubbed network error after a phase prefix.
/// - [`X402Error::UnexpectedAuthEntries`]: the first simulation's
///   authorization is not the single unsigned payer entry for the built
///   `transfer` that step 4 requires, or the re-simulation returned
///   authorization entries other than the signed entries. Its `detail` names
///   the failed check and carries no value from the answer.
/// - [`X402Error::AuthEntrySignFailed`]: auth-entry signing failure.
/// - [`X402Error::TransactionBuildFailed`]: XDR envelope build failure, or
///   re-simulation transaction data that does not decode.
/// - Whatever `before_transmit` returns, unchanged, when the gate refuses.
///
/// # Panics
///
/// Never panics.
#[allow(
    clippy::too_many_lines,
    reason = "step-ordered payment-construction flow; splitting into sub-functions \
              would obscure the sequential validate, identify, build, simulate, sign, \
              gate, re-simulate, serialize ordering"
)]
pub async fn create_payment(
    requirements: &PaymentRequirements,
    signer: &(dyn Signer + Send + Sync),
    client: &StellarRpcClient,
    cross_check: &SorobanCrossCheck,
    profile_passphrase: &str,
    identity_deadline: Instant,
    before_transmit: impl FnOnce(&AuthorizationToTransmit<'_>) -> Result<(), X402Error>,
) -> Result<CreatedPayment, X402Error> {
    // ── Step 1: Validate ──────────────────────────────────────────────────────
    let amount = validate_requirements(requirements, profile_passphrase, client.url())?;
    // `validate_requirements` holds the requirement's passphrase equal to the
    // profile's, so this is the network the payment is built for.
    let network_passphrase = profile_passphrase;

    // ── Step 2: Endpoint identity, the client's first request ────────────────
    // The endpoint answers every later request of this payment, so it must be
    // shown to serve the profile's network before it is asked anything else.
    let identity = client
        .endpoint_identity(network_passphrase, identity_deadline)
        .await
        .map_err(X402Error::EndpointIdentity)?;

    // ── Step 3: Build SAC transfer InvokeHostFunction ─────────────────────────
    // SEP-41: transfer(from: Address, to: Address, amount: i128)
    let payer_key = signer
        .public_key()
        .await
        .map_err(|e| X402Error::RpcSimulateFailed {
            detail: format!("signer public_key fetch failed: {e}"),
        })?;
    let payer_strkey: String = payer_key.to_string().as_str().to_owned();

    let invoke_args = build_sac_transfer_invoke(
        &requirements.asset,
        &payer_strkey,
        &requirements.pay_to,
        amount,
    )?;

    let host_fn = HostFunction::InvokeContract(invoke_args.clone());
    let op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: host_fn,
            auth: VecM::default(),
        }),
    };

    // ── Step 4: First simulateTransaction ─────────────────────────────────────
    // The simulate response populates the auth-entry nonce; the wallet does
    // not generate one.

    // The transaction source is a placeholder at sequence 0; the facilitator
    // rebuilds with its own account as the source before settling. Using a
    // source distinct from the payer is what surfaces the payer's `transfer`
    // authorization as a signable `Address` auth entry.
    let mut source_account = placeholder_source_account()?;

    let mut tx_builder = TransactionBuilder::new(&mut source_account, network_passphrase, None);
    tx_builder.fee(BASE_FEE_STROOPS);
    tx_builder.add_operation(op.clone());
    let tx_for_simulate = tx_builder.build_for_simulation();

    let sim_envelope = tx_for_simulate
        .to_envelope()
        .map_err(|e| X402Error::RpcSimulateFailed {
            detail: format!("first simulate: to_envelope failed: {e:?}"),
        })?;
    let sim_response = client
        .simulate_transaction_envelope(&sim_envelope)
        .await
        .map_err(|e| X402Error::RpcSimulateFailed {
            detail: format!("{}{e}", FIRST_SIMULATION.request_failed),
        })?;

    let first_min_resource_fee = check_simulation_answer(&sim_response, &FIRST_SIMULATION)?;
    let first_transaction_data =
        sim_response
            .transaction_data()
            .map_err(|_| X402Error::RpcSimulateFailed {
                detail: FIRST_SIMULATION_DATA_UNDECODABLE.to_owned(),
            })?;
    check_transaction_data(
        &first_transaction_data,
        first_min_resource_fee,
        &FIRST_SIMULATION,
    )?;

    // Extract the auth entry containing the simulated nonce. The transfer is
    // one host function call, so the answer holds exactly one result.
    let results = sim_response
        .results()
        .map_err(|e| X402Error::RpcSimulateFailed {
            detail: format!("simulate results decode failed: {e}"),
        })?;
    let [first_result] =
        <[_; 1]>::try_from(results).map_err(|results: Vec<_>| X402Error::RpcSimulateFailed {
            detail: if results.is_empty() {
                "simulate returned no result entry"
            } else {
                "simulation returned more than one result"
            }
            .to_owned(),
        })?;

    // The answer decides what the payer would sign, so it is checked before
    // anything is signed: exactly the payer's unsigned entry, for exactly the
    // transfer built above, with no nested calls.
    let payer_sc_address = crate::sac_transfer::g_strkey_to_account_address(&payer_strkey)?;
    let (mut payer_credentials, simulated_invocation) =
        select_payer_auth_entry(first_result.auth, &payer_sc_address)?;
    check_payer_auth_entry(&payer_credentials, &simulated_invocation, &invoke_args)?;

    // The x402 Exact Stellar formula, with the window clamped to 60 ledgers.
    let simulation_ledger = sim_response.latest_ledger;
    let signature_expiration_ledger =
        compute_signature_expiration_ledger(simulation_ledger, requirements.max_timeout_seconds)
            .ok_or_else(|| X402Error::RpcSimulateFailed {
                detail: "the simulation's latest ledger leaves no room for the signature \
                         expiration window"
                    .to_owned(),
            })?;

    // ── Step 5: Cross-check witness and ledger consistency ────────────────────
    // The oracle simulates the envelope the primary simulated, before anything
    // is signed. A refusal returns here; the payer's key is never used.
    let cross_check = cross_check
        .witness(SorobanWitnessInputs {
            envelope: &sim_envelope,
            primary: &sim_response,
            expiration_ledger: signature_expiration_ledger,
            resource_fee_ceiling: u64::from(MAX_RESOURCE_FEE_STROOPS),
        })
        .await
        .map_err(X402Error::CrossCheck)?;

    // The health read runs on the same client under the identity deadline, so
    // the ledgers it compares come from the endpoint the identity check named.
    let health = client
        .get_health_within(identity_deadline)
        .await
        .map_err(|_| X402Error::RpcSimulateFailed {
            detail: "the endpoint's health could not be read".to_owned(),
        })?;
    if health.status != HEALTHY_STATUS {
        return Err(X402Error::RpcSimulateFailed {
            detail: "the endpoint reports a health status other than healthy".to_owned(),
        });
    }
    let health_ledger = health.latest_ledger;
    check_simulation_ledger(
        simulation_ledger,
        health_ledger,
        signature_expiration_ledger,
    )?;

    // ── Step 6: Set expiration, build the signing preimage, sign, and embed ───
    // The simulated credentials carry signature_expiration_ledger = 0. Overwrite
    // it with the computed value, construct the
    // HashIdPreimage::SorobanAuthorization the signer authorizes over, sign it
    // via the single auth-signing call site, then embed the resulting
    // classic-account signature into the entry. The signed invocation is the
    // transfer built in step 3; the step 4 check holds the simulated invocation
    // equal to it.
    payer_credentials.signature_expiration_ledger = signature_expiration_ledger;
    let root_invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(invoke_args.clone()),
        sub_invocations: VecM::default(),
    };

    // `sign_soroban_auth_entry` validates that `network_id` matches the active
    // network and signs SHA-256 of this preimage.
    let network_id = Hash(Sha256::digest(network_passphrase.as_bytes()).into());
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id,
        nonce: payer_credentials.nonce,
        signature_expiration_ledger,
        invocation: root_invocation.clone(),
    });
    let preimage_xdr =
        preimage
            .to_xdr_base64(Limits::none())
            .map_err(|e| X402Error::TransactionBuildFailed {
                detail: format!("auth preimage to_xdr_base64 failed: {e}"),
            })?;

    let raw_signature_b64 = sign_soroban_auth_entry(
        &preimage_xdr,
        signer,
        &payer_key,
        network_passphrase,
        None, // no override: the passphrase was validated above
    )
    .await?; // #[from] Sep43Error -> X402Error::AuthEntrySignFailed

    let signature_bytes: [u8; 64] = BASE64_STANDARD
        .decode(&raw_signature_b64)
        .map_err(|e| X402Error::TransactionBuildFailed {
            detail: format!("auth signature is not valid base64: {e}"),
        })?
        .try_into()
        .map_err(|v: Vec<u8>| X402Error::TransactionBuildFailed {
            detail: format!("auth signature is {} bytes, expected 64", v.len()),
        })?;

    // The payer's public key was validated as a G-strkey above; re-parse for the
    // signature map's `public_key` field.
    let payer_pubkey_bytes: [u8; 32] = match Strkey::from_string(&payer_strkey) {
        Ok(Strkey::PublicKeyEd25519(pk)) => pk.0,
        _ => {
            return Err(X402Error::TransactionBuildFailed {
                detail: "payer strkey is not a G-strkey".to_owned(),
            });
        }
    };

    payer_credentials.signature = g_key_sig_to_scval(&payer_pubkey_bytes, &signature_bytes)?;
    let signed_entries = vec![SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(payer_credentials),
        root_invocation,
    }];

    // ── Step 7: Re-simulation envelope, then the transmit gate ───────────────
    // The envelope is built first, so every step that can still fail without
    // sending anything runs before the gate.

    let invoke_args_for_resim = invoke_args.clone();
    let auth_vecm: VecM<SorobanAuthorizationEntry> =
        signed_entries
            .clone()
            .try_into()
            .map_err(|e| X402Error::TransactionBuildFailed {
                detail: format!("auth VecM for re-simulate construction failed: {e:?}"),
            })?;

    let resim_op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(invoke_args_for_resim),
            auth: auth_vecm,
        }),
    };

    // Re-simulate with the same placeholder source; the facilitator re-sources
    // before settling.
    let mut source_account2 = placeholder_source_account()?;

    let mut resim_builder = TransactionBuilder::new(&mut source_account2, network_passphrase, None);
    resim_builder.fee(BASE_FEE_STROOPS);
    resim_builder.add_operation(resim_op);
    let resim_tx = resim_builder.build_for_simulation();

    let resim_envelope = resim_tx
        .to_envelope()
        .map_err(|e| X402Error::RpcSimulateFailed {
            detail: format!("re-simulate: to_envelope failed: {e:?}"),
        })?;

    // The request below is the first one carrying the signed authorization.
    // The gate runs immediately before it and after every step that can still
    // fail without sending anything, so a gate that recorded the authorization
    // and returned `Ok` is always followed by that request. A refusal returns
    // here, and the signature never leaves the wallet.
    before_transmit(&AuthorizationToTransmit {
        network: &requirements.network,
        scheme: &requirements.scheme,
        payer: &payer_strkey,
        pay_to: &requirements.pay_to,
        asset: &requirements.asset,
        amount,
        signature_expiration_ledger,
        cross_check: cross_check.witness(),
    })?;

    // ── Step 8: Re-simulate with signed auth (MANDATORY) ─────────────────────
    // Without re-simulation, submit traps with:
    //   "trying to access contract data key outside of the footprint"
    // because the signed auth entry changes the storage read-set.
    let resim_response = client
        .simulate_transaction_envelope(&resim_envelope)
        .await
        .map_err(|e| X402Error::RpcSimulateFailed {
            detail: format!("{}{e}", RESIMULATION.request_failed),
        })?;

    let resource_fee = check_simulation_answer(&resim_response, &RESIMULATION)?;
    // A malformed footprint fails closed: a footprint-less envelope cannot
    // settle, so the error is surfaced rather than producing an unsubmittable
    // payload.
    let soroban_data =
        resim_response
            .transaction_data()
            .map_err(|e| X402Error::TransactionBuildFailed {
                detail: format!("re-simulate transaction_data decode failed: {e}"),
            })?;
    check_transaction_data(&soroban_data, resource_fee, &RESIMULATION)?;

    // The answer returns no authorization other than the signed entries. The
    // final envelope below carries the wallet's own signed entries.
    check_resimulation_auth(&resim_response, &signed_entries)?;

    let resimulation_ledger = resim_response.latest_ledger;
    check_resimulation_ledger(
        health_ledger,
        resimulation_ledger,
        signature_expiration_ledger,
    )?;
    tracing::debug!(
        protocol_version = identity.protocol_version(),
        simulation_ledger,
        health_ledger,
        resimulation_ledger,
        signature_expiration_ledger,
        "x402 payment ledgers checked"
    );

    // ── Step 9: Build final envelope and serialize ────────────────────────────
    let auth_vecm_final: VecM<SorobanAuthorizationEntry> =
        signed_entries
            .try_into()
            .map_err(|e| X402Error::TransactionBuildFailed {
                detail: format!("final auth VecM construction failed: {e:?}"),
            })?;

    let final_op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(invoke_args),
            auth: auth_vecm_final,
        }),
    };

    // Build the final envelope with the same placeholder source; the facilitator
    // re-sources before settling.
    let mut source_account3 = placeholder_source_account()?;

    let mut final_builder = TransactionBuilder::new(&mut source_account3, network_passphrase, None);
    // `resource_fee` is at most MAX_RESOURCE_FEE_STROOPS, and the compile-time
    // assertion beside that constant shows the sum fits `u32`.
    final_builder.fee(BASE_FEE_STROOPS.saturating_add(resource_fee));
    final_builder.add_operation(final_op);
    let mut final_tx = final_builder.build_for_simulation();

    // Transaction::soroban_data becomes TransactionExt::V1 on to_envelope().
    final_tx.soroban_data = Some(soroban_data);

    let envelope = final_tx
        .to_envelope()
        .map_err(|e| X402Error::TransactionBuildFailed {
            detail: format!("Transaction::to_envelope failed: {e:?}"),
        })?;

    let transaction_xdr =
        envelope
            .to_xdr_base64(Limits::none())
            .map_err(|e| X402Error::TransactionBuildFailed {
                detail: format!("envelope to_xdr_base64 failed: {e}"),
            })?;

    // ── Step 10: Wrap in PaymentPayload ───────────────────────────────────────
    Ok(CreatedPayment {
        payload: PaymentPayload {
            x402_version: 2,
            resource: None,
            accepted: requirements.clone(),
            payload: ExactStellarPayloadV2 {
                transaction: transaction_xdr,
            },
            extensions: None,
        },
        cross_check,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Simulation answer checks
// ─────────────────────────────────────────────────────────────────────────────

/// The fixed refusal details of one simulation phase.
struct SimulationPhase {
    /// Prefix of the detail of a request that failed; the scrubbed network
    /// error follows it.
    request_failed: &'static str,
    /// Prefix of the detail of an answer that carries an error.
    answer_error: &'static str,
    /// The answer carries a restore preamble.
    restore_preamble: &'static str,
    /// The answer carries no minimum resource fee or no transaction data.
    no_fee_or_data: &'static str,
    /// The minimum resource fee exceeds [`MAX_RESOURCE_FEE_STROOPS`].
    fee_ceiling: &'static str,
    /// The transaction data lists archived entries to restore.
    archived_entries: &'static str,
    /// The transaction data embeds a resource fee outside
    /// `0..=min_resource_fee`.
    embedded_fee: &'static str,
}

/// The unsigned first simulation.
const FIRST_SIMULATION: SimulationPhase = SimulationPhase {
    request_failed: "first simulation request failed: ",
    answer_error: "simulate returned error: ",
    restore_preamble: "the simulation returned a restore preamble; this wallet does not restore \
                       archived ledger entries",
    no_fee_or_data: "simulate returned no min_resource_fee / transaction_data",
    fee_ceiling: "the simulation's minimum resource fee exceeds the wallet's ceiling of \
                  10000000 stroops",
    archived_entries: "the simulation's transaction data restores archived ledger entries; this \
                       wallet does not restore them",
    embedded_fee: "the simulation's transaction data embeds a resource fee outside zero to its \
                   minimum resource fee",
};

/// The signed re-simulation.
const RESIMULATION: SimulationPhase = SimulationPhase {
    request_failed: "re-simulation request failed: ",
    answer_error: "re-simulate returned error: ",
    restore_preamble: "the re-simulation returned a restore preamble; this wallet does not \
                       restore archived ledger entries",
    no_fee_or_data: "re-simulate returned no min_resource_fee / transaction_data",
    fee_ceiling: "the re-simulation's minimum resource fee exceeds the wallet's ceiling of \
                  10000000 stroops",
    archived_entries: "the re-simulation's transaction data restores archived ledger entries; \
                       this wallet does not restore them",
    embedded_fee: "the re-simulation's transaction data embeds a resource fee outside zero to \
                   its minimum resource fee",
};

/// The first simulation's transaction data does not decode.
const FIRST_SIMULATION_DATA_UNDECODABLE: &str = "the simulation's transaction data does not decode";

/// Checks the parts of a simulation answer that precede its transaction data
/// and its authorization, and returns its minimum resource fee.
///
/// In order: the answer carries no error and no restore preamble, and it
/// carries transaction data and a minimum resource fee in
/// `1..=MAX_RESOURCE_FEE_STROOPS`.
///
/// # Errors
///
/// [`X402Error::RpcSimulateFailed`] with the phase's detail for the first
/// failed check. Only the error check carries the answer's own text.
fn check_simulation_answer(
    response: &SimulateTransactionResponse,
    phase: &SimulationPhase,
) -> Result<u32, X402Error> {
    let refuse = |detail: &str| X402Error::RpcSimulateFailed {
        detail: detail.to_owned(),
    };
    if let Some(ref error) = response.error {
        return Err(X402Error::RpcSimulateFailed {
            detail: format!("{}{error}", phase.answer_error),
        });
    }
    if response.restore_preamble.is_some() {
        return Err(refuse(phase.restore_preamble));
    }
    if response.min_resource_fee == 0 || response.transaction_data.is_empty() {
        return Err(refuse(phase.no_fee_or_data));
    }
    if response.min_resource_fee > u64::from(MAX_RESOURCE_FEE_STROOPS) {
        return Err(refuse(phase.fee_ceiling));
    }
    // The ceiling above is a `u32`, so the conversion succeeds.
    u32::try_from(response.min_resource_fee).map_err(|_| refuse(phase.fee_ceiling))
}

/// Checks decoded simulation transaction data against the answer's minimum
/// resource fee.
///
/// The data lists no archived entries to restore, and its embedded resource
/// fee lies in `0..=min_resource_fee`.
///
/// # Errors
///
/// [`X402Error::RpcSimulateFailed`] with the phase's fixed detail.
fn check_transaction_data(
    data: &SorobanTransactionData,
    min_resource_fee: u32,
    phase: &SimulationPhase,
) -> Result<(), X402Error> {
    let refuse = |detail: &str| X402Error::RpcSimulateFailed {
        detail: detail.to_owned(),
    };
    if let SorobanTransactionDataExt::V1(ext) = &data.ext
        && !ext.archived_soroban_entries.is_empty()
    {
        return Err(refuse(phase.archived_entries));
    }
    if data.resource_fee < 0 || data.resource_fee > i64::from(min_resource_fee) {
        return Err(refuse(phase.embedded_fee));
    }
    Ok(())
}

/// Checks the first simulation's ledger `simulation` against the health
/// ledger `health` and the signature expiration ledger `expiration`.
///
/// `simulation` is above zero and at most one ledger ahead of `health`, which
/// tolerates one ledger of skew between load-balanced backends. `health` lies
/// before `expiration`, so the authorization is not expired when it is signed.
///
/// # Errors
///
/// [`X402Error::RpcSimulateFailed`] with a fixed detail naming the failed
/// predicate.
fn check_simulation_ledger(simulation: u32, health: u32, expiration: u32) -> Result<(), X402Error> {
    let refuse = |detail: &str| X402Error::RpcSimulateFailed {
        detail: detail.to_owned(),
    };
    if simulation == 0 {
        return Err(refuse("the simulation reports ledger zero"));
    }
    if simulation > health.saturating_add(1) {
        return Err(refuse(
            "the simulation reports a ledger more than one ahead of the endpoint's health",
        ));
    }
    if health >= expiration {
        return Err(refuse(
            "the endpoint's health ledger has reached the signature expiration ledger",
        ));
    }
    Ok(())
}

/// Checks the re-simulation's ledger `resimulation` against the health ledger
/// `health` and the signature expiration ledger `expiration`.
///
/// `resimulation` is at most one ledger behind `health`, which tolerates one
/// ledger of skew between load-balanced backends, and lies before
/// `expiration`.
///
/// # Errors
///
/// [`X402Error::RpcSimulateFailed`] with a fixed detail naming the failed
/// predicate.
fn check_resimulation_ledger(
    health: u32,
    resimulation: u32,
    expiration: u32,
) -> Result<(), X402Error> {
    let refuse = |detail: &str| X402Error::RpcSimulateFailed {
        detail: detail.to_owned(),
    };
    if health > resimulation.saturating_add(1) {
        return Err(refuse(
            "the re-simulation reports a ledger more than one behind the endpoint's health",
        ));
    }
    if resimulation >= expiration {
        return Err(refuse(
            "the re-simulation reports a ledger at or past the signature expiration ledger",
        ));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Builds a [`BaselibAccount`] for the placeholder transaction source at
/// sequence 0.
///
/// See [`PLACEHOLDER_SOURCE`]: the payer authorizes via the signed auth entry,
/// and the facilitator rebuilds the transaction with its own source before
/// settling, so this placeholder is never used on-chain.
///
/// # Errors
///
/// - [`X402Error::TransactionBuildFailed`]: the placeholder account cannot be
///   constructed. The placeholder strkey is a compile-time constant, so this
///   is unreachable in practice.
fn placeholder_source_account() -> Result<BaselibAccount, X402Error> {
    BaselibAccount::new(PLACEHOLDER_SOURCE, "0").map_err(|e| X402Error::TransactionBuildFailed {
        detail: format!("placeholder source account construction failed: {e:?}"),
    })
}

/// Returns the signature window in ledgers for a requirement's
/// `maxTimeoutSeconds`: `ceil(min(seconds, 300) / 5)`.
///
/// The requirement names a maximum validity, so clamping it to
/// [`MAX_SIGNED_VALIDITY_SECONDS`] signs a shorter validity that still meets
/// it. A validated requirement carries at least one second, so the window lies
/// in `1..=60`.
fn expiration_window_ledgers(max_timeout_seconds: u32) -> u32 {
    max_timeout_seconds
        .min(MAX_SIGNED_VALIDITY_SECONDS)
        .div_ceil(ESTIMATED_LEDGER_CLOSE_SECONDS)
}

/// Computes the auth-entry `signature_expiration_ledger` as
/// `latest_ledger + expiration_window_ledgers(max_timeout_seconds)`, the x402
/// Exact Stellar scheme expiration formula with a clamped window.
///
/// Returns `None` when the sum overflows `u32`: no valid expiration ledger
/// exists for that `latest_ledger`.
fn compute_signature_expiration_ledger(
    latest_ledger: u32,
    max_timeout_seconds: u32,
) -> Option<u32> {
    latest_ledger.checked_add(expiration_window_ledgers(max_timeout_seconds))
}

/// Builds the classic-account signature `ScVal` for the
/// `SorobanAddressCredentials.signature` field.
///
/// The Soroban host expects a `Vec` of signature maps (one per signer); each map
/// is `{ "public_key": Bytes(32), "signature": Bytes(64) }`. A G-key payer is a
/// single signer, so the outer vector holds exactly one map.
///
/// # Errors
///
/// - [`X402Error::TransactionBuildFailed`] — if an XDR container exceeds its
///   length limit, which cannot occur for these fixed-size inputs.
fn g_key_sig_to_scval(pubkey: &[u8; 32], sig: &[u8; 64]) -> Result<ScVal, X402Error> {
    let pubkey_sym = ScVal::Symbol(ScSymbol(
        StringM::try_from("public_key".to_owned()).map_err(|e| {
            X402Error::TransactionBuildFailed {
                detail: format!("ScSymbol public_key: {e}"),
            }
        })?,
    ));
    let pubkey_val = ScVal::Bytes(ScBytes(pubkey.to_vec().try_into().map_err(|e| {
        X402Error::TransactionBuildFailed {
            detail: format!("public_key bytes: {e}"),
        }
    })?));
    let sig_sym = ScVal::Symbol(ScSymbol(
        StringM::try_from("signature".to_owned()).map_err(|e| {
            X402Error::TransactionBuildFailed {
                detail: format!("ScSymbol signature: {e}"),
            }
        })?,
    ));
    let sig_val = ScVal::Bytes(ScBytes(sig.to_vec().try_into().map_err(|e| {
        X402Error::TransactionBuildFailed {
            detail: format!("signature bytes: {e}"),
        }
    })?));

    let inner_map = ScMap(
        vec![
            ScMapEntry {
                key: pubkey_sym,
                val: pubkey_val,
            },
            ScMapEntry {
                key: sig_sym,
                val: sig_val,
            },
        ]
        .try_into()
        .map_err(|e| X402Error::TransactionBuildFailed {
            detail: format!("signature ScMap: {e}"),
        })?,
    );

    let outer_vec = ScVec(vec![ScVal::Map(Some(inner_map))].try_into().map_err(|e| {
        X402Error::TransactionBuildFailed {
            detail: format!("signature ScVec: {e}"),
        }
    })?);

    Ok(ScVal::Vec(Some(outer_vec)))
}

/// Takes the payer's authorization entry from the first simulation's answer.
///
/// A SAC `transfer` from a G-account payer distinct from the transaction
/// source needs exactly the payer's signature. The answer must therefore hold
/// exactly one entry, with legacy `Address` credentials whose address is the
/// payer.
/// The count covers every credential arm: an empty answer, a second payer
/// entry, a `SourceAccount` entry, and an entry for another account beside the
/// payer's all refuse. `AddressV2` and `AddressWithDelegates` credentials
/// refuse because this flow signs only the legacy preimage.
///
/// Returns the payer's credentials and the entry's root invocation, which
/// [`check_payer_auth_entry`] then checks against the built transfer.
///
/// # Errors
///
/// - [`X402Error::UnexpectedAuthEntries`]: the answer does not hold exactly
///   one entry, the entry's credentials are not legacy `Address` credentials,
///   or they are for an account other than the payer. The detail names the
///   failed check and carries no value from the answer.
fn select_payer_auth_entry(
    entries: Vec<SorobanAuthorizationEntry>,
    payer_sc_address: &ScAddress,
) -> Result<(SorobanAddressCredentials, SorobanAuthorizedInvocation), X402Error> {
    let [entry] = <[SorobanAuthorizationEntry; 1]>::try_from(entries).map_err(|_| {
        unexpected_auth_entries(
            "the simulation must return exactly one authorization entry, the payer's",
        )
    })?;
    let credentials = match entry.credentials {
        SorobanCredentials::Address(credentials) => credentials,
        SorobanCredentials::SourceAccount => {
            return Err(unexpected_auth_entries(
                "the simulated authorization entry has source-account credentials, \
                 not the payer's address credentials",
            ));
        }
        SorobanCredentials::AddressV2(_) => {
            return Err(unexpected_auth_entries(
                "the simulated authorization entry has AddressV2 credentials; \
                 this flow signs legacy address credentials only",
            ));
        }
        SorobanCredentials::AddressWithDelegates(_) => {
            return Err(unexpected_auth_entries(
                "the simulated authorization entry has delegated address credentials; \
                 this flow signs legacy address credentials only",
            ));
        }
    };
    if credentials.address != *payer_sc_address {
        return Err(unexpected_auth_entries(
            "the simulated authorization entry is for an account other than the payer",
        ));
    }
    Ok((credentials, entry.root_invocation))
}

/// Checks the payer's simulated authorization against the transfer the
/// wallet built, before anything is signed.
///
/// A recording simulation returns the entry unsigned: a zero
/// `signature_expiration_ledger` and a `Void` signature. Its root invocation
/// must equal `built`, contract, function name, and every argument included,
/// and it must carry no nested calls. The payer then signs exactly the
/// transfer that the transmit gate, the policy, and the audit row describe.
///
/// # Errors
///
/// - [`X402Error::UnexpectedAuthEntries`]: any of these checks fails. The
///   detail names the failed check and carries no value from the answer.
fn check_payer_auth_entry(
    credentials: &SorobanAddressCredentials,
    invocation: &SorobanAuthorizedInvocation,
    built: &InvokeContractArgs,
) -> Result<(), X402Error> {
    if credentials.signature_expiration_ledger != 0 {
        return Err(unexpected_auth_entries(
            "the simulated authorization entry has a non-zero signature expiration ledger",
        ));
    }
    if credentials.signature != ScVal::Void {
        return Err(unexpected_auth_entries(
            "the simulated authorization entry already carries a signature",
        ));
    }
    if let Some(detail) = root_function_difference(&invocation.function, built) {
        return Err(unexpected_auth_entries(detail));
    }
    if !invocation.sub_invocations.is_empty() {
        return Err(unexpected_auth_entries(
            "the simulated root invocation carries nested calls",
        ));
    }
    Ok(())
}

/// Compares a simulated root function with the built SEP-41
/// `transfer(from, to, amount)` and names the first part that differs, for a
/// refusal detail.
///
/// `built` is the three-argument transfer that [`build_sac_transfer_invoke`]
/// builds. Returns `None` exactly when `simulated` equals
/// `ContractFn(built)`: the contract, the function name, and the three
/// arguments in order. An argument list of any other length gets the count
/// detail.
fn root_function_difference(
    simulated: &SorobanAuthorizedFunction,
    built: &InvokeContractArgs,
) -> Option<&'static str> {
    let SorobanAuthorizedFunction::ContractFn(simulated) = simulated else {
        return Some("the simulated root invocation is not a contract call");
    };
    if simulated.contract_address != built.contract_address {
        return Some("the simulated root invocation calls a contract other than the payment asset");
    }
    if simulated.function_name != built.function_name {
        return Some("the simulated root invocation calls a function other than transfer");
    }
    let ([from, to, amount], [built_from, built_to, built_amount]) =
        (simulated.args.as_slice(), built.args.as_slice())
    else {
        return Some(
            "the simulated root invocation passes a different number of arguments \
             than transfer(from, to, amount)",
        );
    };
    if from != built_from {
        return Some("the simulated root invocation passes a from argument other than the payer");
    }
    if to != built_to {
        return Some("the simulated root invocation passes a to argument other than payTo");
    }
    if amount != built_amount {
        return Some(
            "the simulated root invocation passes an amount other than the required amount",
        );
    }
    None
}

/// Checks the authorization entries of the answer to the signed
/// re-simulation.
///
/// The answer must carry a first result that decodes. Its authorization
/// entries are either empty or equal to `signed`, entry for entry; an
/// enforcing simulation returns the supplied entries unchanged. A missing or
/// undecodable result is a failed simulation, never an empty authorization.
///
/// # Errors
///
/// - [`X402Error::RpcSimulateFailed`]: the answer carries no result, or its
///   results do not decode.
/// - [`X402Error::UnexpectedAuthEntries`]: the first result's authorization
///   entries are neither empty nor equal to `signed`.
fn check_resimulation_auth(
    response: &stellar_rpc_client::SimulateTransactionResponse,
    signed: &[SorobanAuthorizationEntry],
) -> Result<(), X402Error> {
    let results = response
        .results()
        .map_err(|_| X402Error::RpcSimulateFailed {
            detail: "the re-simulation results do not decode".to_owned(),
        })?;
    let Some(result) = results.first() else {
        return Err(X402Error::RpcSimulateFailed {
            detail: "the re-simulation returned no result".to_owned(),
        });
    };
    if !result.auth.is_empty() && result.auth.as_slice() != signed {
        return Err(unexpected_auth_entries(
            "the re-simulation returned authorization entries other than the signed entry",
        ));
    }
    Ok(())
}

/// Builds [`X402Error::UnexpectedAuthEntries`] with a wallet-written detail.
fn unexpected_auth_entries(detail: &str) -> X402Error {
    X402Error::UnexpectedAuthEntries {
        detail: detail.to_owned(),
    }
}

/// Validates that `strkey` is a C-strkey (contract address).
///
/// # Errors
///
/// - [`X402Error::InvalidAssetAddress`] if the strkey is malformed or not a
///   C-type.
fn validate_c_strkey(strkey: &str) -> Result<(), X402Error> {
    match Strkey::from_string(strkey) {
        Ok(Strkey::Contract(_)) => Ok(()),
        Ok(_other) => Err(X402Error::InvalidAssetAddress {
            detail: format!(
                "expected C-strkey (contract), got non-contract strkey: {}",
                quote_server_text(strkey)
            ),
        }),
        Err(e) => Err(X402Error::InvalidAssetAddress {
            detail: format!("strkey parse failed for {}: {e}", quote_server_text(strkey)),
        }),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics and unwraps acceptable in unit tests"
    )]

    use super::*;
    use stellar_xdr::{AccountId, PublicKey, SorobanAddressCredentialsWithDelegates, Uint256};

    // ── select_payer_auth_entry ───────────────────────────────────────────────

    /// Builds a minimal `SorobanAuthorizationEntry` with `Address` credentials
    /// for the given `ScAddress`.
    fn make_address_entry(addr: ScAddress) -> SorobanAuthorizationEntry {
        use stellar_xdr::{ContractId, InvokeContractArgs, ScSymbol, ScVal};
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: addr,
                nonce: 0,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                    contract_address: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
                    function_name: ScSymbol("transfer".try_into().unwrap()),
                    args: VecM::default(),
                }),
                sub_invocations: VecM::default(),
            },
        }
    }

    fn payer_sc_address() -> ScAddress {
        // All-zero 32-byte ed25519 public key — structurally valid G-strkey.
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            [0u8; 32],
        ))))
    }

    fn foreign_sc_address() -> ScAddress {
        // Different account — foreign payer.
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes))))
    }

    /// The payer's entry with its credentials moved into another arm.
    fn payer_entry_with_credentials(
        arm: impl FnOnce(SorobanAddressCredentials) -> SorobanCredentials,
    ) -> SorobanAuthorizationEntry {
        let mut entry = make_address_entry(payer_sc_address());
        let SorobanCredentials::Address(credentials) = entry.credentials else {
            panic!("make_address_entry builds Address credentials");
        };
        entry.credentials = arm(credentials);
        entry
    }

    /// The count refusal's detail.
    const COUNT_DETAIL: &str =
        "the simulation must return exactly one authorization entry, the payer's";

    /// Asserts that selection refuses with exactly `expected` as its detail.
    fn assert_selection_refused(entries: Vec<SorobanAuthorizationEntry>, expected: &str) {
        match select_payer_auth_entry(entries, &payer_sc_address()) {
            Err(X402Error::UnexpectedAuthEntries { detail }) => {
                assert_eq!(detail, expected, "the refusal detail");
            }
            other => panic!("expected UnexpectedAuthEntries {expected:?}, got {other:?}"),
        }
    }

    /// Exactly one payer entry → selection returns its credentials and root
    /// invocation.
    #[test]
    fn select_payer_auth_entry_single_match_ok() {
        let entry = make_address_entry(payer_sc_address());
        let (credentials, invocation) =
            select_payer_auth_entry(vec![entry.clone()], &payer_sc_address()).unwrap();
        assert_eq!(SorobanCredentials::Address(credentials), entry.credentials);
        assert_eq!(invocation, entry.root_invocation);
    }

    /// A sole Address entry for another account → refused by the payer check.
    #[test]
    fn select_payer_auth_entry_foreign_entry_only_rejects() {
        assert_selection_refused(
            vec![make_address_entry(foreign_sc_address())],
            "the simulated authorization entry is for an account other than the payer",
        );
    }

    /// A sole `SourceAccount` entry → refused by the credential-arm check.
    #[test]
    fn select_payer_auth_entry_only_source_account_rejects() {
        assert_selection_refused(
            vec![payer_entry_with_credentials(|_| {
                SorobanCredentials::SourceAccount
            })],
            "the simulated authorization entry has source-account credentials, \
             not the payer's address credentials",
        );
    }

    /// The payer's entry with `AddressV2` credentials → refused by the
    /// credential-arm check.
    #[test]
    fn select_payer_auth_entry_address_v2_rejects() {
        assert_selection_refused(
            vec![payer_entry_with_credentials(SorobanCredentials::AddressV2)],
            "the simulated authorization entry has AddressV2 credentials; \
             this flow signs legacy address credentials only",
        );
    }

    /// The payer's entry with delegated credentials → refused by the
    /// credential-arm check.
    #[test]
    fn select_payer_auth_entry_delegated_credentials_rejects() {
        assert_selection_refused(
            vec![payer_entry_with_credentials(|address_credentials| {
                SorobanCredentials::AddressWithDelegates(SorobanAddressCredentialsWithDelegates {
                    address_credentials,
                    delegates: VecM::default(),
                })
            })],
            "the simulated authorization entry has delegated address credentials; \
             this flow signs legacy address credentials only",
        );
    }

    /// Two payer entries → refused by the count.
    #[test]
    fn select_payer_auth_entry_multiple_payer_matches_rejects() {
        assert_selection_refused(
            vec![
                make_address_entry(payer_sc_address()),
                make_address_entry(payer_sc_address()),
            ],
            COUNT_DETAIL,
        );
    }

    /// One payer entry + one foreign Account entry → refused by the count: a
    /// SAC `transfer` from a G-key payer needs exactly the payer's signature.
    #[test]
    fn select_payer_auth_entry_foreign_account_entry_rejects() {
        assert_selection_refused(
            vec![
                make_address_entry(payer_sc_address()),
                make_address_entry(foreign_sc_address()),
            ],
            COUNT_DETAIL,
        );
    }

    /// Empty auth entries → refused by the count.
    #[test]
    fn select_payer_auth_entry_empty_entries_rejects() {
        assert_selection_refused(Vec::new(), COUNT_DETAIL);
    }

    /// One payer entry + one `SourceAccount` entry → refused by the count,
    /// which covers every credential arm.
    #[test]
    fn select_payer_auth_entry_source_account_beside_payer_rejects() {
        let source_entry = payer_entry_with_credentials(|_| SorobanCredentials::SourceAccount);
        assert_selection_refused(
            vec![make_address_entry(payer_sc_address()), source_entry],
            COUNT_DETAIL,
        );
    }

    // ── validate_c_strkey ──────────────────────────────────────────────────────

    #[test]
    fn c_strkey_accepted() {
        let c = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
        assert!(validate_c_strkey(c).is_ok());
    }

    #[test]
    fn g_strkey_rejected() {
        // Valid G-strkey (the all-zero public key) — should be rejected as a C-strkey.
        let g = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
        assert!(matches!(
            validate_c_strkey(g),
            Err(X402Error::InvalidAssetAddress { .. })
        ));
    }

    #[test]
    fn malformed_strkey_rejected() {
        assert!(matches!(
            validate_c_strkey("not-a-strkey"),
            Err(X402Error::InvalidAssetAddress { .. })
        ));
    }

    // ── signature_expiration_ledger formula ────────────────────────────────────

    #[test]
    fn expiration_formula_300s_timeout() {
        // 300 / 5 = 60 ledgers, latest = 1000, expiration = 1060 (exact multiple).
        assert_eq!(compute_signature_expiration_ledger(1000, 300), Some(1060));
    }

    #[test]
    fn expiration_formula_rounds_up_for_non_multiple() {
        // 6 / 5 = 1.2, ceil = 2; 1 / 5 = 0.2, ceil = 1.
        assert_eq!(compute_signature_expiration_ledger(1000, 6), Some(1002));
        assert_eq!(compute_signature_expiration_ledger(1000, 1), Some(1001));
    }

    #[test]
    fn expiration_formula_clamps_the_window_at_sixty_ledgers() {
        // A requirement above 300 s signs the 300 s window: 60 ledgers.
        assert_eq!(compute_signature_expiration_ledger(1000, 301), Some(1060));
        assert_eq!(
            compute_signature_expiration_ledger(1000, u32::MAX),
            Some(1060)
        );
    }

    #[test]
    fn expiration_formula_refuses_on_overflow() {
        // The last ledger with room for a 60-ledger window still computes;
        // one more has no valid expiration ledger.
        assert_eq!(
            compute_signature_expiration_ledger(u32::MAX - 60, 300),
            Some(u32::MAX)
        );
        assert_eq!(
            compute_signature_expiration_ledger(u32::MAX - 59, 300),
            None
        );
        assert_eq!(
            compute_signature_expiration_ledger(u32::MAX, u32::MAX),
            None
        );
    }

    // ── placeholder_source_account ─────────────────────────────────────────────

    #[test]
    fn placeholder_source_account_constructs() {
        assert!(
            placeholder_source_account().is_ok(),
            "placeholder source account must construct from the constant strkey"
        );
    }

    // ── g_key_sig_to_scval ─────────────────────────────────────────────────────

    /// The classic-account signature ScVal must be `Vec([Map{public_key:
    /// Bytes(32), signature: Bytes(64)}])`, with the public key and signature in
    /// their correct fields (not swapped).
    #[test]
    fn g_key_sig_to_scval_shape() {
        let pubkey = [7u8; 32];
        let sig = [9u8; 64];
        let scval = g_key_sig_to_scval(&pubkey, &sig).unwrap();

        let ScVal::Vec(Some(outer)) = scval else {
            panic!("signature ScVal must be a Vec");
        };
        assert_eq!(outer.len(), 1, "exactly one signer map");

        let ScVal::Map(Some(map)) = &outer[0] else {
            panic!("signer entry must be a Map");
        };
        assert_eq!(map.len(), 2, "map has public_key + signature");

        let mut saw_pubkey = false;
        let mut saw_signature = false;
        for entry in map.iter() {
            let ScVal::Symbol(key) = &entry.key else {
                panic!("map key must be a Symbol");
            };
            match key.0.to_utf8_string_lossy().as_str() {
                "public_key" => {
                    saw_pubkey = true;
                    let ScVal::Bytes(b) = &entry.val else {
                        panic!("public_key value must be Bytes");
                    };
                    assert_eq!(b.0.len(), 32);
                    assert_eq!(b.0.as_slice(), &pubkey);
                }
                "signature" => {
                    saw_signature = true;
                    let ScVal::Bytes(b) = &entry.val else {
                        panic!("signature value must be Bytes");
                    };
                    assert_eq!(b.0.len(), 64);
                    assert_eq!(b.0.as_slice(), &sig);
                }
                other => panic!("unexpected map key: {other}"),
            }
        }
        assert!(saw_pubkey && saw_signature, "both fields present");
    }
}
