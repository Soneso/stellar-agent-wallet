//! Exact Stellar scheme orchestrator — constructs a signed SAC `transfer`
//! payment payload compatible with the x402 v2 `PAYMENT-SIGNATURE` wire format.
//!
//! # Eight-step flow
//!
//! ```text
//! 1. Validate requirements (scheme, network, asset, areFeesSponsored, amount)
//! 2. Build SAC transfer InvokeHostFunction
//! 3. simulateTransaction → harvest simulated nonce + latest_ledger
//! 4. Compute signature_expiration_ledger
//! 5. Set expiration on auth entry; sign via sep43 (single auth-signing call site)
//! 6. Re-simulate with signed auth (mandatory footprint refresh)
//! 7. Build + serialize final TransactionEnvelope to base64 XDR
//! 8. Wrap in PaymentPayload
//! ```
//!
//! The flow matches the @x402/stellar reference implementation.  Auth-entry
//! signing goes through a single call site
//! (`stellar_agent_sep43::sign_soroban_auth_entry`).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use sha2::{Digest as _, Sha256};
use stellar_baselib::account::{Account as BaselibAccount, AccountBehavior};
use stellar_baselib::transaction::TransactionBehavior;
use stellar_baselib::transaction_builder::{TransactionBuilder, TransactionBuilderBehavior};
use stellar_rpc_client::Client;
use stellar_strkey::Strkey;
use stellar_xdr::{
    Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, HostFunction, InvokeHostFunctionOp,
    Limits, Operation, OperationBody, ScAddress, ScBytes, ScMap, ScMapEntry, ScSymbol, ScVal,
    ScVec, SorobanAuthorizationEntry, SorobanCredentials, StringM, VecM, WriteXdr,
};

use stellar_agent_network::signing::Signer;
use stellar_agent_sep43::signing::sign_soroban_auth_entry;

use crate::X402Error;
use crate::constants::x402_network_to_passphrase;
use crate::sac_transfer::build_sac_transfer_invoke;
use crate::wire::{ExactStellarPayloadV2, PaymentPayload, PaymentRequirements};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Base transaction fee in stroops used for simulate and re-simulate builds.
///
/// The resource fee from simulate is added on top.
const BASE_FEE_STROOPS: u32 = 100;

/// Estimated ledger close time in seconds for x402 expiration calculation.
///
/// Fallback default `5`; the @x402/stellar reference implementation samples
/// recent Horizon ledgers and averages the inter-close intervals, falling back
/// to `5` seconds on error.  We pin the documented default constant.
///
/// Used in: `signature_expiration_ledger = latest_ledger + ceil(max_timeout_seconds / 5)`.
const ESTIMATED_LEDGER_CLOSE_SECONDS: u32 = 5;

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
// create_payment
// ─────────────────────────────────────────────────────────────────────────────

/// Constructs a signed x402 v2 [`PaymentPayload`] for the Exact Stellar scheme.
///
/// Implements the eight-step flow, wire-compatible with the @x402/stellar
/// reference implementation.
///
/// # Steps
///
/// 1. Validate `requirements` (scheme, network, asset, `areFeesSponsored`,
///    amount > 0).
/// 2. Build a SAC `transfer` `InvokeHostFunction`.
/// 3. `simulateTransaction` to populate the auth-entry nonce and
///    `latest_ledger`.
/// 4. Compute `signature_expiration_ledger` from `max_timeout_seconds` via the
///    formula `latest_ledger + ceil(max_timeout_seconds / 5)`, giving
///    expiration parity with the x402 Exact Stellar scheme.
/// 5. Verify the simulate-returned auth-entry array satisfies the single-payer
///    invariant (exactly one `Address` entry for the payer; no other
///    `Address`-credentialled entries).  Set `signature_expiration_ledger` on
///    the payer entry and sign via `stellar_agent_sep43::sign_soroban_auth_entry`
///    (the single auth-signing call site).
/// 6. Re-simulate with the signed auth entry (MANDATORY).  Without this, submit
///    traps with "trying to access contract data key outside of the footprint".
/// 7. Build the final `TransactionEnvelope`, serialize to base64 XDR.
/// 8. Wrap in a [`PaymentPayload`].
///
/// # Arguments
///
/// - `requirements` — validated payment requirements from the 402 header.
/// - `signer` — signer implementation providing the payer's key.
/// - `rpc_url` — Soroban RPC URL (from operator profile; NEVER from the
///   payment-required body).
/// - `profile_passphrase` — the network passphrase from the operator's profile
///   used to cross-check the `requirements.network` field.
///
/// # Errors
///
/// - [`X402Error::UnsupportedScheme`] — scheme is not `"exact"`.
/// - [`X402Error::UnsupportedNetwork`] — network not in `{stellar:pubnet, stellar:testnet}`.
/// - [`X402Error::NetworkPassphraseMismatch`] — network passphrase mismatch.
/// - [`X402Error::InvalidAssetAddress`] — `asset` is not a valid C-strkey.
/// - [`X402Error::FeesNotSponsored`] — `extra.areFeesSponsored != true`.
/// - [`X402Error::AmountConversion`] — `amount` parse failure.
/// - [`X402Error::RpcSimulateFailed`] — simulate or re-simulate failure, or
///   `min_resource_fee` absent on the success path.
/// - [`X402Error::UnexpectedAuthEntries`] — simulate returned zero, multiple,
///   or non-payer `Address`-credentialled entries (single-payer invariant
///   violated).
/// - [`X402Error::AuthEntrySignFailed`] — auth-entry signing failure.
/// - [`X402Error::TransactionBuildFailed`] — XDR envelope build failure.
///
/// # Panics
///
/// Never panics.
#[allow(
    clippy::too_many_lines,
    reason = "eight-step payment-construction flow; splitting into sub-functions \
              would obscure the sequential validate→build→sim→sign→resim→serialize \
              invariant ordering"
)]
pub async fn create_payment(
    requirements: &PaymentRequirements,
    signer: &(dyn Signer + Send + Sync),
    rpc_url: &str,
    profile_passphrase: &str,
) -> Result<PaymentPayload, X402Error> {
    // ── Step 1: Validate ──────────────────────────────────────────────────────

    if requirements.scheme != "exact" {
        return Err(X402Error::UnsupportedScheme {
            scheme: requirements.scheme.clone(),
        });
    }

    // Map x402 wire network → passphrase.
    // x402 uses "stellar:pubnet"; Caip2 uses "stellar:mainnet".
    let network_passphrase = x402_network_to_passphrase(&requirements.network)?;
    if network_passphrase != profile_passphrase {
        return Err(X402Error::NetworkPassphraseMismatch {
            network: requirements.network.clone(),
            expected_passphrase: network_passphrase,
            profile_passphrase: profile_passphrase.to_owned(),
        });
    }

    // Validate asset is a C-strkey.
    validate_c_strkey(&requirements.asset)?;

    // Hard precondition: areFeesSponsored must be true.
    // INTENTIONAL DIVERGENCE from upstream: upstream uses JS-truthy `if
    // (!extra.areFeesSponsored)`, which accepts `"true"`, `1`, or any non-null
    // value.  We require the strict JSON `Bool(true)` form — rejecting
    // ambiguous encodings such as `"true"` or `1`.  This is a hardening choice.
    if requirements.extra.get("areFeesSponsored") != Some(&serde_json::Value::Bool(true)) {
        return Err(X402Error::FeesNotSponsored);
    }

    // Parse amount from the wire format (already atomic units — do NOT
    // re-apply decimals; the wire `amount` is an integer string).
    // The amount must be a positive integer; zero is explicitly invalid.
    let amount: i128 =
        requirements
            .amount
            .parse::<i128>()
            .map_err(|e| X402Error::AmountConversion {
                detail: format!(
                    "wire amount {:?} is not a valid i128: {e}",
                    requirements.amount
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

    // ── Step 2: Build SAC transfer InvokeHostFunction ─────────────────────────
    // SEP-41: transfer(from: Address, to: Address, amount: i128)

    // signer.public_key() returns stellar_strkey::ed25519::PublicKey directly;
    // no PublicKey(pk.0) re-wrap needed.
    // to_string() on stellar_strkey types returns heapless::String<56>;
    // as_str().to_owned() converts to std::String.
    let payer_strkey: String = signer
        .public_key()
        .await
        .map_err(|e| X402Error::RpcSimulateFailed {
            detail: format!("signer public_key fetch failed: {e}"),
        })?
        .to_string()
        .as_str()
        .to_owned();

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

    // ── Step 3: First simulateTransaction → simulated nonce ───────────────────
    // The simulate response populates the auth-entry nonce — we do NOT generate
    // one.

    let server = Client::new(rpc_url).map_err(|e| X402Error::RpcSimulateFailed {
        detail: format!("stellar-rpc-client Client construction failed: {e}"),
    })?;

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
    let sim_response = server
        .simulate_transaction_envelope(&sim_envelope, None)
        .await
        .map_err(|e| X402Error::RpcSimulateFailed {
            detail: format!("first simulate_transaction_envelope failed: {e}"),
        })?;

    if let Some(ref sim_error) = sim_response.error {
        return Err(X402Error::RpcSimulateFailed {
            detail: format!("simulate returned error: {sim_error}"),
        });
    }

    if sim_response.min_resource_fee == 0 || sim_response.transaction_data.is_empty() {
        return Err(X402Error::RpcSimulateFailed {
            detail: "simulate returned no min_resource_fee / transaction_data".to_owned(),
        });
    }

    // Extract the auth entry containing the simulated nonce.
    let first_result = sim_response
        .results()
        .map_err(|e| X402Error::RpcSimulateFailed {
            detail: format!("simulate results decode failed: {e}"),
        })?
        .into_iter()
        .next()
        .ok_or_else(|| X402Error::RpcSimulateFailed {
            detail: "simulate returned no result entry".to_owned(),
        })?;
    let mut auth_entries = first_result.auth;

    // Verify the auth-entry array satisfies the single-payer invariant.
    //
    // For a plain G-key SAC `transfer`, the scheme requires that exactly the
    // payer must sign, and that after signing no other signers remain.
    //
    // Concretely we require:
    //   (a) exactly one Address-credentialled entry whose `c.address` equals the
    //       payer's `ScAddress::Account(...)`,
    //   (b) no OTHER Address-credentialled entry present (foreign signer → reject).
    let payer_sc_address = crate::sac_transfer::g_strkey_to_account_address(&payer_strkey)?;
    let auth_entry = select_payer_auth_entry(&mut auth_entries, &payer_sc_address)?;

    // ── Step 4: Compute signature_expiration_ledger ───────────────────────────
    // The x402 Exact Stellar scheme formula (NOT a fixed auth-validity window)
    // gives wire-interop expiration parity.
    let latest_ledger = sim_response.latest_ledger;
    let signature_expiration_ledger =
        compute_signature_expiration_ledger(latest_ledger, requirements.max_timeout_seconds);

    // ── Step 5: Set expiration, build the signing preimage, sign, and embed ───
    // The simulated auth entry carries signature_expiration_ledger = 0. Overwrite
    // it with the computed value, construct the
    // HashIdPreimage::SorobanAuthorization the signer authorizes over, sign it
    // via the single auth-signing call site, then embed the resulting
    // classic-account signature into the entry.

    let creds_nonce = match &mut auth_entry.credentials {
        SorobanCredentials::Address(creds) => {
            creds.signature_expiration_ledger = signature_expiration_ledger;
            creds.nonce
        }
        SorobanCredentials::SourceAccount
        | SorobanCredentials::AddressV2(_)
        | SorobanCredentials::AddressWithDelegates(_) => {
            return Err(X402Error::UnexpectedAuthEntries {
                detail: "payer auth entry is not Address-credentialled".to_owned(),
            });
        }
    };

    // `sign_soroban_auth_entry` validates that `network_id` matches the active
    // network and signs SHA-256 of this preimage.
    let network_id = Hash(Sha256::digest(network_passphrase.as_bytes()).into());
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id,
        nonce: creds_nonce,
        signature_expiration_ledger,
        invocation: auth_entry.root_invocation.clone(),
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
        network_passphrase,
        None, // no override — passphrase already validated above
    )
    .await?; // #[from] Sep43Error → X402Error::AuthEntrySignFailed

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

    let signature_scval = g_key_sig_to_scval(&payer_pubkey_bytes, &signature_bytes)?;
    if let SorobanCredentials::Address(ref mut creds) = auth_entry.credentials {
        creds.signature = signature_scval;
    }
    let signed_entries = vec![auth_entry.clone()];

    // ── Step 6: Re-simulate with signed auth (MANDATORY) ─────────────────────
    // Without re-simulation, submit traps with:
    //   "trying to access contract data key outside of the footprint"
    // because the signed auth entry changes the storage read-set.

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
    let resim_response = server
        .simulate_transaction_envelope(&resim_envelope, None)
        .await
        .map_err(|e| X402Error::RpcSimulateFailed {
            detail: format!("re-simulate: simulate_transaction_envelope failed: {e}"),
        })?;

    if let Some(ref resim_error) = resim_response.error {
        return Err(X402Error::RpcSimulateFailed {
            detail: format!("re-simulate returned error: {resim_error}"),
        });
    }
    if resim_response.min_resource_fee == 0 || resim_response.transaction_data.is_empty() {
        return Err(X402Error::RpcSimulateFailed {
            detail: "re-simulate returned no min_resource_fee / transaction_data".to_owned(),
        });
    }

    // ── Step 7: Build final envelope and serialize ────────────────────────────
    // Attach the soroban transaction data (resource footprint + refundable fee)
    // from the re-simulate response.
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

    // Parse min resource fee from re-simulate.
    let resource_fee = parse_min_resource_fee(&resim_response)?;

    // Build the final envelope with the same placeholder source; the facilitator
    // re-sources before settling.
    let mut source_account3 = placeholder_source_account()?;

    let mut final_builder = TransactionBuilder::new(&mut source_account3, network_passphrase, None);
    final_builder.fee(BASE_FEE_STROOPS.saturating_add(resource_fee));
    final_builder.add_operation(final_op);
    let mut final_tx = final_builder.build_for_simulation();

    // Attach the soroban transaction data (resource footprint + refundable fee).
    // Transaction::soroban_data → TransactionExt::V1 on to_envelope(). A malformed
    // footprint must fail closed: a footprint-less envelope cannot settle, so the
    // error is surfaced rather than silently producing an unsubmittable payload.
    let soroban_data =
        resim_response
            .transaction_data()
            .map_err(|e| X402Error::TransactionBuildFailed {
                detail: format!("re-simulate transaction_data decode failed: {e}"),
            })?;
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

    // ── Step 8: Wrap in PaymentPayload ────────────────────────────────────────
    Ok(PaymentPayload {
        x402_version: 2,
        resource: None,
        accepted: requirements.clone(),
        payload: ExactStellarPayloadV2 {
            transaction: transaction_xdr,
        },
        extensions: None,
    })
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
/// - [`X402Error::TransactionBuildFailed`] — if the placeholder account cannot
///   be constructed (the placeholder strkey is a compile-time constant, so this
///   is unreachable in practice).
fn placeholder_source_account() -> Result<BaselibAccount, X402Error> {
    BaselibAccount::new(PLACEHOLDER_SOURCE, "0").map_err(|e| X402Error::TransactionBuildFailed {
        detail: format!("placeholder source account construction failed: {e:?}"),
    })
}

/// Computes the auth-entry `signature_expiration_ledger` as
/// `latest_ledger + ceil(max_timeout_seconds / ESTIMATED_LEDGER_CLOSE_SECONDS)`,
/// the x402 Exact Stellar scheme expiration formula.
///
/// Saturating arithmetic clamps an overflowing window to `u32::MAX`.
fn compute_signature_expiration_ledger(latest_ledger: u32, max_timeout_seconds: u32) -> u32 {
    let ledger_window = u32::try_from(
        u64::from(max_timeout_seconds).div_ceil(u64::from(ESTIMATED_LEDGER_CLOSE_SECONDS)),
    )
    .unwrap_or(u32::MAX);
    latest_ledger.saturating_add(ledger_window)
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

/// Selects the auth entry credentialed for the payer's own account.
///
/// Enforces the single-payer invariant required for a G-key SAC `transfer`:
/// - Exactly one address-bearing entry must authorize as `payer_sc_address`.
/// - No other address-bearing entry may be present.
///
/// This realises the x402 Exact Stellar scheme invariant that exactly the payer
/// must sign and that no other signers remain after signing. All address-bearing
/// credential variants (`Address`, `AddressV2`, `AddressWithDelegates`) are
/// considered; `SourceAccount` entries are ignored.
///
/// # Errors
///
/// - [`X402Error::UnexpectedAuthEntries`] — zero, multiple, or non-payer
///   address-bearing entries are present.
fn select_payer_auth_entry<'a>(
    entries: &'a mut [SorobanAuthorizationEntry],
    payer_sc_address: &ScAddress,
) -> Result<&'a mut SorobanAuthorizationEntry, X402Error> {
    let payer_indices: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| credential_address(&e.credentials) == Some(payer_sc_address))
        .map(|(i, _)| i)
        .collect();

    let foreign_address_count = entries
        .iter()
        .filter(|e| credential_address(&e.credentials).is_some_and(|a| a != payer_sc_address))
        .count();

    // Reject if any foreign address-bearing entry exists.
    if foreign_address_count > 0 {
        return Err(X402Error::UnexpectedAuthEntries {
            detail: format!(
                "simulate returned {foreign_address_count} address-bearing \
                 entry(ies) for accounts other than the payer; a G-key SAC transfer \
                 must need only the payer's signature"
            ),
        });
    }

    match payer_indices.len() {
        0 => Err(X402Error::UnexpectedAuthEntries {
            detail: "simulate returned no address-bearing auth entry for the payer; \
                     expected exactly one for a G-key SAC transfer"
                .to_owned(),
        }),
        1 => Ok(&mut entries[payer_indices[0]]),
        n => Err(X402Error::UnexpectedAuthEntries {
            detail: format!(
                "simulate returned {n} address-bearing entries for the payer; \
                 expected exactly one"
            ),
        }),
    }
}

/// Returns the authorizing `ScAddress` for any address-bearing credential
/// variant (`Address`, `AddressV2`, `AddressWithDelegates`), or `None` for
/// `SourceAccount`.
fn credential_address(credentials: &SorobanCredentials) -> Option<&ScAddress> {
    match credentials {
        SorobanCredentials::Address(c) | SorobanCredentials::AddressV2(c) => Some(&c.address),
        SorobanCredentials::AddressWithDelegates(d) => Some(&d.address_credentials.address),
        SorobanCredentials::SourceAccount => None,
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
            detail: format!("expected C-strkey (contract), got non-contract strkey: {strkey:?}"),
        }),
        Err(e) => Err(X402Error::InvalidAssetAddress {
            detail: format!("strkey parse failed for {strkey:?}: {e}"),
        }),
    }
}

/// Parses the `min_resource_fee` from a simulate response.
///
/// Casts the u64 field down to the u32 the fee builder requires.
/// The `== 0` guard above makes a zero value unreachable on the success path,
/// but we reject casts that overflow rather than silently truncating.
///
/// # Errors
///
/// - [`X402Error::TransactionBuildFailed`] — the u64 value does not fit in
///   `u32`.
fn parse_min_resource_fee(
    sim: &stellar_rpc_client::SimulateTransactionResponse,
) -> Result<u32, X402Error> {
    u32::try_from(sim.min_resource_fee).map_err(|e| X402Error::TransactionBuildFailed {
        detail: format!("min_resource_fee u64->u32 cast failed: {e}"),
    })
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
    use stellar_xdr::{
        AccountId, Hash, PublicKey, SorobanAddressCredentials, SorobanAuthorizedFunction,
        SorobanAuthorizedInvocation, Uint256,
    };

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

    /// Exactly one payer entry → selection succeeds.
    #[test]
    fn select_payer_auth_entry_single_match_ok() {
        let mut entries = vec![make_address_entry(payer_sc_address())];
        let result = select_payer_auth_entry(&mut entries, &payer_sc_address());
        assert!(result.is_ok(), "single payer entry should succeed");
    }

    /// A foreign Address entry with no payer match → `UnexpectedAuthEntries`
    /// via the foreign-entry guard.
    #[test]
    fn select_payer_auth_entry_foreign_entry_only_rejects() {
        let mut entries = vec![make_address_entry(foreign_sc_address())];
        // foreign_sc_address is not the payer: payer_indices is empty AND
        // foreign_address_count is 1, so the foreign-entry guard fires first.
        let result = select_payer_auth_entry(&mut entries, &payer_sc_address());
        assert!(
            matches!(result, Err(X402Error::UnexpectedAuthEntries { .. })),
            "expected UnexpectedAuthEntries, got {result:?}"
        );
    }

    /// A non-empty array with no Address entries (only `SourceAccount`) → the
    /// zero-payer-match arm rejects with `UnexpectedAuthEntries`.
    #[test]
    fn select_payer_auth_entry_only_source_account_rejects() {
        let source_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::SourceAccount,
            root_invocation: make_address_entry(payer_sc_address()).root_invocation,
        };
        let mut entries = vec![source_entry];
        let result = select_payer_auth_entry(&mut entries, &payer_sc_address());
        assert!(
            matches!(result, Err(X402Error::UnexpectedAuthEntries { .. })),
            "no Address entry for the payer must reject, got {result:?}"
        );
    }

    /// Multiple payer-matching entries → `UnexpectedAuthEntries`.
    #[test]
    fn select_payer_auth_entry_multiple_payer_matches_rejects() {
        let mut entries = vec![
            make_address_entry(payer_sc_address()),
            make_address_entry(payer_sc_address()),
        ];
        let result = select_payer_auth_entry(&mut entries, &payer_sc_address());
        assert!(
            matches!(result, Err(X402Error::UnexpectedAuthEntries { .. })),
            "expected UnexpectedAuthEntries for duplicate payer entries, got {result:?}"
        );
    }

    /// One payer entry + one foreign Account entry → `UnexpectedAuthEntries`.
    ///
    /// This is the "no other signers required" invariant: a SAC `transfer` for
    /// a G-key payer must need exactly the payer's signature.
    #[test]
    fn select_payer_auth_entry_foreign_account_entry_rejects() {
        let mut entries = vec![
            make_address_entry(payer_sc_address()),
            make_address_entry(foreign_sc_address()),
        ];
        let result = select_payer_auth_entry(&mut entries, &payer_sc_address());
        assert!(
            matches!(result, Err(X402Error::UnexpectedAuthEntries { .. })),
            "expected UnexpectedAuthEntries for foreign account entry, got {result:?}"
        );
    }

    /// Empty auth entries → `UnexpectedAuthEntries`.
    #[test]
    fn select_payer_auth_entry_empty_entries_rejects() {
        let mut entries: Vec<SorobanAuthorizationEntry> = vec![];
        let result = select_payer_auth_entry(&mut entries, &payer_sc_address());
        assert!(
            matches!(result, Err(X402Error::UnexpectedAuthEntries { .. })),
            "expected UnexpectedAuthEntries for empty entries, got {result:?}"
        );
    }

    /// `SourceAccount`-credentialled entries are ignored in the
    /// foreign-entry check; only the payer's `Address` entry matters.
    #[test]
    fn select_payer_auth_entry_ignores_source_account_entries() {
        use stellar_xdr::{ContractId, InvokeContractArgs, ScSymbol};
        let source_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::SourceAccount,
            root_invocation: SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                    contract_address: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
                    function_name: ScSymbol("transfer".try_into().unwrap()),
                    args: VecM::default(),
                }),
                sub_invocations: VecM::default(),
            },
        };
        let mut entries = vec![make_address_entry(payer_sc_address()), source_entry];
        let result = select_payer_auth_entry(&mut entries, &payer_sc_address());
        // SourceAccount entry is not an Address-credentialled entry, so it
        // should not trigger the foreign-entry guard.
        assert!(
            result.is_ok(),
            "SourceAccount entry alongside payer entry should succeed, got {result:?}"
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
        // 300 / 5 = 60 ledgers, latest = 1000 → expiration = 1060 (exact multiple)
        assert_eq!(compute_signature_expiration_ledger(1000, 300), 1060);
    }

    #[test]
    fn expiration_formula_rounds_up_for_non_multiple() {
        // 301 / 5 = 60.2 → ceil = 61, latest = 1000 → expiration = 1061
        assert_eq!(compute_signature_expiration_ledger(1000, 301), 1061);
    }

    #[test]
    fn expiration_formula_saturates_on_overflow() {
        // A huge timeout near u32::MAX seconds clamps the window, and the
        // ledger sum saturates rather than wrapping.
        assert_eq!(
            compute_signature_expiration_ledger(u32::MAX, u32::MAX),
            u32::MAX
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
