//! The envelope-bound witness producers.
//!
//! The unbound producers compare the observations a decision read with the
//! oracle; they do not know which transaction the decision is for. The bound
//! producers take that transaction too, and before any requirement decision
//! they check that it is the transaction the observations describe:
//!
//! - classic: the envelope's source is the input's source (or the pool's
//!   funder), its sequence is the observed sequence plus one, and its
//!   operations are the ones the input kind builds, naming the observed
//!   accounts and assets; a payment's memo observation is `NotRead` exactly
//!   when the envelope carries a memo or pays a muxed destination; and the
//!   value of a payment or an account creation is a
//!   [`CrossCheckValue::Amount`] equal to the payment's asset and amount, or
//!   to the starting balance in native stroops;
//! - Soroban: the primary simulation authorizes exactly the payer, for
//!   exactly the expected root invocation, and the envelope invokes that
//!   root's contract function.
//!
//! A mismatch refuses with `network.witness_unavailable` before any oracle
//! request, whatever the requirement rule would decide. A passed witness
//! carries the subject: the network transaction hash of a classic envelope,
//! which signatures do not change, or the Soroban intent digest of a payment.

use stellar_agent_core::cross_check::{
    CrossCheckRequirement, CrossCheckValue, ThresholdSet, cross_check_requirement,
};
use stellar_agent_core::error::{NetworkError, WalletError, WitnessUnavailableReason};
use stellar_agent_core::profile::schema::Profile;
use stellar_xdr::{
    AccountId, Asset as XdrAsset, ChangeTrustAsset, ClaimableBalanceId, HostFunction, Memo,
    MuxedAccount, Operation, OperationBody, PublicKey, ReadXdr as _, ScAddress,
    SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials, Transaction,
    TransactionEnvelope, Uint256,
};

use super::{
    ClassicInputs, CrossCheckOutcome, SorobanCrossCheck, SorobanWitnessInputs,
    WITNESS_ATTEMPT_BUDGET, WITNESS_RETRY_BACKOFF, WitnessTiming, classic_witness, soroban,
    warn_skipped,
};
use crate::context::NetworkContext;

fn mismatch(part: &'static str) -> WalletError {
    NetworkError::WitnessUnavailable {
        reason: WitnessUnavailableReason::EnvelopeMismatch { part },
    }
    .into()
}

fn ensure(holds: bool, part: &'static str) -> Result<(), WalletError> {
    if holds { Ok(()) } else { Err(mismatch(part)) }
}

fn strkey(key: [u8; 32]) -> String {
    stellar_strkey::ed25519::PublicKey(key)
        .to_string()
        .to_string()
}

fn account_of(account: &AccountId) -> String {
    let AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key))) = account;
    strkey(*key)
}

fn muxed_of(account: &MuxedAccount) -> String {
    match account {
        MuxedAccount::Ed25519(Uint256(key)) => strkey(*key),
        MuxedAccount::MuxedEd25519(muxed) => strkey(muxed.ed25519.0),
    }
}

/// Whether `op` carries no source of its own or carries `source`.
fn op_source_is(op: &Operation, source: &str) -> bool {
    op.source_account
        .as_ref()
        .is_none_or(|account| muxed_of(account) == source)
}

fn code_text(code: &[u8]) -> String {
    String::from_utf8_lossy(code)
        .trim_end_matches('\0')
        .to_owned()
}

/// The canonical identity of a classic XDR asset; `None` for native.
fn canonical_asset(
    asset: &XdrAsset,
) -> Result<Option<stellar_agent_core::asset_id::CanonicalAsset>, WalletError> {
    let (code, issuer) = match asset {
        XdrAsset::Native => return Ok(None),
        XdrAsset::CreditAlphanum4(a) => (code_text(&a.asset_code.0), account_of(&a.issuer)),
        XdrAsset::CreditAlphanum12(a) => (code_text(&a.asset_code.0), account_of(&a.issuer)),
    };
    stellar_agent_core::asset_id::CanonicalAsset::classic(&code, &issuer)
        .map(Some)
        .map_err(|_| mismatch("operation"))
}

/// The issuer a `ChangeTrust` line names; `None` for a native or pool line.
fn change_trust_issuer(line: &ChangeTrustAsset) -> Option<String> {
    match line {
        ChangeTrustAsset::CreditAlphanum4(a) => Some(account_of(&a.issuer)),
        ChangeTrustAsset::CreditAlphanum12(a) => Some(account_of(&a.issuer)),
        ChangeTrustAsset::Native | ChangeTrustAsset::PoolShare(_) => None,
    }
}

/// Checks the envelope's operations against the input kind.
fn check_operations(
    inputs: &ClassicInputs,
    ops: &[Operation],
    source: &str,
) -> Result<(), WalletError> {
    match inputs {
        ClassicInputs::Pay(v) => {
            let [op] = ops else {
                return Err(mismatch("operation"));
            };
            let OperationBody::Payment(payment) = &op.body else {
                return Err(mismatch("operation"));
            };
            ensure(op_source_is(op, source), "operation")?;
            ensure(
                muxed_of(&payment.destination) == v.destination.account_id,
                "operation",
            )?;
            let asset = canonical_asset(&payment.asset)?;
            match (&v.trustline, asset) {
                (None, None) => Ok(()),
                (Some(trustline), Some(asset)) => ensure(
                    trustline.asset == asset && trustline.account_id == source,
                    "operation",
                ),
                _ => Err(mismatch("operation")),
            }
        }
        ClassicInputs::CreateAccount(_) => {
            let [op] = ops else {
                return Err(mismatch("operation"));
            };
            ensure(
                matches!(op.body, OperationBody::CreateAccount(_)) && op_source_is(op, source),
                "operation",
            )
        }
        ClassicInputs::Trustline(v) => {
            let [op] = ops else {
                return Err(mismatch("operation"));
            };
            let OperationBody::ChangeTrust(change) = &op.body else {
                return Err(mismatch("operation"));
            };
            ensure(
                op_source_is(op, source)
                    && change_trust_issuer(&change.line).as_deref()
                        == Some(v.issuer.account_id.as_str()),
                "operation",
            )
        }
        ClassicInputs::Claim(v) => {
            let [op] = ops else {
                return Err(mismatch("operation"));
            };
            let OperationBody::ClaimClaimableBalance(claim) = &op.body else {
                return Err(mismatch("operation"));
            };
            let ClaimableBalanceId::ClaimableBalanceIdTypeV0(id) = &claim.balance_id;
            ensure(
                op_source_is(op, source) && v.balance.as_ref().is_none_or(|b| b.balance_id == id.0),
                "operation",
            )
        }
        ClassicInputs::PoolInit(v) => {
            let (triples, rest) = ops.as_chunks::<3>();
            ensure(
                !ops.is_empty() && rest.is_empty() && triples.len() == v.absent_channels.len(),
                "operation",
            )?;
            for ([begin, create, end], channel) in triples.iter().zip(&v.absent_channels) {
                let begins = matches!(
                    &begin.body,
                    OperationBody::BeginSponsoringFutureReserves(op)
                        if account_of(&op.sponsored_id) == *channel
                ) && op_source_is(begin, source);
                let creates = matches!(
                    &create.body,
                    OperationBody::CreateAccount(op) if account_of(&op.destination) == *channel
                ) && op_source_is(create, source);
                let ends = matches!(end.body, OperationBody::EndSponsoringFutureReserves)
                    && end
                        .source_account
                        .as_ref()
                        .is_some_and(|account| muxed_of(account) == *channel);
                ensure(begins && creates && ends, "operation")?;
            }
            Ok(())
        }
    }
}

/// Decodes the unsigned classic envelope once; the subject, memo, and value
/// checks read the decoded value.
fn decode_classic_envelope(envelope_b64: &str) -> Result<TransactionEnvelope, WalletError> {
    TransactionEnvelope::from_xdr_base64(
        envelope_b64,
        stellar_agent_xdr_limits::untrusted_decode_limits(envelope_b64.len()),
    )
    .map_err(|_| mismatch("envelope"))
}

/// The transaction of a classic `Tx` envelope; any other envelope refuses.
fn classic_transaction(envelope: &TransactionEnvelope) -> Result<&Transaction, WalletError> {
    match envelope {
        TransactionEnvelope::Tx(v1) => Ok(&v1.tx),
        _ => Err(mismatch("envelope")),
    }
}

/// Checks the envelope against the inputs, including a payment's memo
/// observation, and returns its network transaction hash.
pub(super) fn classic_subject(
    inputs: &ClassicInputs,
    envelope: &TransactionEnvelope,
    network_passphrase: &str,
) -> Result<[u8; 32], WalletError> {
    let tx = classic_transaction(envelope)?;
    let source = match inputs {
        ClassicInputs::Pay(v) => &v.source,
        ClassicInputs::CreateAccount(v) => &v.source,
        ClassicInputs::Trustline(v) => &v.source,
        ClassicInputs::Claim(v) => &v.source,
        ClassicInputs::PoolInit(v) => &v.funder,
    };
    ensure(muxed_of(&tx.source_account) == source.account_id, "source")?;
    ensure(
        source.sequence.checked_add(1) == Some(tx.seq_num.0),
        "sequence",
    )?;
    check_operations(inputs, &tx.operations, &source.account_id)?;
    if let ClassicInputs::Pay(payment) = inputs {
        let muxed_destination = tx.operations.iter().any(|op| {
            matches!(
                &op.body, OperationBody::Payment(op)
                    if matches!(op.destination, MuxedAccount::MuxedEd25519(_))
            )
        });
        ensure(
            matches!(payment.memo, super::inputs::MemoObservation::NotRead)
                == (!matches!(tx.memo, Memo::None) || muxed_destination),
            "memo",
        )?;
    }
    let hash = crate::submit::compute_local_tx_hash_hex(envelope, network_passphrase)?;
    stellar_agent_core::hex::decode_hex32(&hash).map_err(|_| mismatch("envelope"))
}

/// Compares the threshold value with the envelope's economic value: a
/// payment's or an account creation's value must be a
/// [`CrossCheckValue::Amount`] of the operation's asset and amount.
fn check_classic_value(
    inputs: &ClassicInputs,
    value: CrossCheckValue<'_>,
    envelope: &TransactionEnvelope,
) -> Result<(), WalletError> {
    let tx = classic_transaction(envelope)?;
    let expected = match (inputs, tx.operations.first().map(|op| &op.body)) {
        (ClassicInputs::Pay(_), Some(OperationBody::Payment(op))) => Some((
            canonical_asset(&op.asset)?
                .unwrap_or(stellar_agent_core::asset_id::CanonicalAsset::Native),
            i128::from(op.amount),
        )),
        (ClassicInputs::CreateAccount(_), Some(OperationBody::CreateAccount(op))) => Some((
            stellar_agent_core::asset_id::CanonicalAsset::Native,
            i128::from(op.starting_balance),
        )),
        _ => None,
    };
    if let Some((expected_asset, expected_amount)) = expected {
        ensure(
            matches!(value, CrossCheckValue::Amount { asset, base_units }
            if *asset == expected_asset && base_units == expected_amount),
            "value",
        )?;
    }
    Ok(())
}

/// Applies the requirement rule under `thresholds` and compares the
/// observations with the oracle, as [`super::obtain_classic_witness`] does,
/// after checking that `unsigned_envelope_b64` is the transaction they
/// describe and that `value` is its economic value. A passed witness carries
/// the envelope's network transaction hash.
///
/// The envelope check covers the source, the sequence, the operations, a
/// payment's memo observation, and the value: a payment or an account
/// creation requires a [`CrossCheckValue::Amount`] equal to the payment's
/// asset and amount, or to the starting balance in native stroops. The check
/// runs first, so a mismatch refuses even where no comparison is required. A
/// signed envelope of the same transaction yields the same hash.
///
/// # Errors
///
/// `network.witness_unavailable` naming the part that does not match
/// (`envelope`, `source`, `sequence`, `operation`, `memo`, or `value`), and
/// every refusal of [`super::obtain_classic_witness`].
pub async fn obtain_classic_witness_bound(
    profile: &Profile,
    context: &NetworkContext,
    value: CrossCheckValue<'_>,
    inputs: impl Into<ClassicInputs>,
    unsigned_envelope_b64: &str,
    thresholds: &ThresholdSet<'_>,
    tool: &'static str,
) -> Result<CrossCheckOutcome, WalletError> {
    obtain_classic_witness_bound_with_timing(
        profile,
        context,
        value,
        inputs.into(),
        unsigned_envelope_b64,
        thresholds,
        tool,
        WitnessTiming {
            attempt_budget: WITNESS_ATTEMPT_BUDGET,
            retry_backoff: WITNESS_RETRY_BACKOFF,
        },
    )
    .await
}

/// [`obtain_classic_witness_bound`] under the given timing.
#[allow(
    clippy::too_many_arguments,
    reason = "the bound producer's inputs and the attempt timing"
)]
pub(crate) async fn obtain_classic_witness_bound_with_timing(
    profile: &Profile,
    context: &NetworkContext,
    value: CrossCheckValue<'_>,
    inputs: ClassicInputs,
    unsigned_envelope_b64: &str,
    thresholds: &ThresholdSet<'_>,
    tool: &'static str,
    timing: WitnessTiming,
) -> Result<CrossCheckOutcome, WalletError> {
    let envelope = decode_classic_envelope(unsigned_envelope_b64)?;
    let subject = classic_subject(&inputs, &envelope, context.network_passphrase())?;
    check_classic_value(&inputs, value, &envelope)?;
    classic_witness(
        profile,
        context,
        value,
        &inputs,
        thresholds,
        Some(subject),
        tool,
        timing,
    )
    .await
}

/// The Soroban payment a bound Soroban witness compares: the primary's
/// simulation, the root invocation the payment authorizes, and the payer.
#[derive(Clone, Copy)]
pub struct BoundSorobanInputs<'a> {
    /// The primary's simulation of the unsigned payment.
    pub inputs: &'a SorobanWitnessInputs<'a>,
    /// The root invocation the payment requirements build.
    pub expected_root: &'a SorobanAuthorizedInvocation,
    /// The payer's G-strkey.
    pub payer: &'a str,
}

/// Checks the simulation against the payer and the root and returns the
/// payment's Soroban intent digest.
pub(super) fn soroban_subject(
    bound: &BoundSorobanInputs<'_>,
    network_passphrase: &str,
) -> Result<[u8; 32], WalletError> {
    let primary = soroban::Primary::decode(bound.inputs)?;
    let payer = stellar_strkey::ed25519::PublicKey::from_string(bound.payer)
        .map_err(|_| mismatch("authorization"))?;
    let payer_address =
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(payer.0))));
    let [entry] = primary.auth.as_slice() else {
        return Err(mismatch("authorization"));
    };
    let SorobanCredentials::Address(credentials) = &entry.credentials else {
        return Err(mismatch("authorization"));
    };
    ensure(
        credentials.address == payer_address && entry.root_invocation == *bound.expected_root,
        "authorization",
    )?;
    let TransactionEnvelope::Tx(v1) = bound.inputs.envelope else {
        return Err(mismatch("envelope"));
    };
    let [op] = v1.tx.operations.as_slice() else {
        return Err(mismatch("operation"));
    };
    let invokes_root = match (&op.body, &bound.expected_root.function) {
        (
            OperationBody::InvokeHostFunction(invoke),
            SorobanAuthorizedFunction::ContractFn(root_args),
        ) => {
            matches!(&invoke.host_function, HostFunction::InvokeContract(args) if args == root_args)
        }
        _ => false,
    };
    ensure(invokes_root, "operation")?;
    let network_id: [u8; 32] =
        <sha2::Sha256 as sha2::Digest>::digest(network_passphrase.as_bytes()).into();
    crate::mainnet::digest::soroban_intent_digest(&network_id, bound.expected_root)
}

/// Applies the requirement rule under `thresholds` and has the oracle
/// simulate the payment, as [`SorobanCrossCheck`] does, after checking that
/// the simulation authorizes exactly the payer for exactly `expected_root`.
/// A passed witness carries the payment's Soroban intent digest.
///
/// The check runs first, so a mismatch refuses even where no comparison is
/// required.
///
/// On mainnet the oracle bounds the ledger of every payment. A payment whose
/// value requires the witness has it from the oracle's simulation. A payment
/// below its threshold has it from the oracle's latest ledger: the oracle
/// answers the mainnet identity, then `getLatestLedger`, and its ledger must
/// trail the primary's simulation ledger by at most two ledgers and lie
/// before the signature expiration ledger. The outcome stays
/// [`CrossCheckOutcome::NotRequired`]. A mainnet profile without
/// `oracle_provider_url` refuses every payment, so a primary alone never
/// decides the ledger a mainnet signature's window derives from. On testnet a
/// payment below its threshold sends no oracle request.
///
/// # Errors
///
/// `network.witness_unavailable` naming the part that does not match, and
/// every refusal of [`SorobanCrossCheck::prepare`] and
/// [`SorobanCrossCheck::witness`]. On mainnet below the threshold:
/// `network.witness_unavailable` with `OracleNotConfigured` when the profile
/// names no oracle, `simulation.divergence` with `LedgerSkew` or `Expiration`
/// when the oracle's ledger is out of bounds, and the oracle read's
/// refusals.
pub async fn obtain_soroban_witness_bound(
    profile: &Profile,
    context: &NetworkContext,
    value: CrossCheckValue<'_>,
    thresholds: &ThresholdSet<'_>,
    bound: &BoundSorobanInputs<'_>,
    tool: &'static str,
) -> Result<CrossCheckOutcome, WalletError> {
    obtain_soroban_witness_bound_with_timing(
        profile,
        context,
        value,
        thresholds,
        bound,
        tool,
        WitnessTiming {
            attempt_budget: WITNESS_ATTEMPT_BUDGET,
            retry_backoff: WITNESS_RETRY_BACKOFF,
        },
    )
    .await
}

/// [`obtain_soroban_witness_bound`] under the given timing.
pub(crate) async fn obtain_soroban_witness_bound_with_timing(
    profile: &Profile,
    context: &NetworkContext,
    value: CrossCheckValue<'_>,
    thresholds: &ThresholdSet<'_>,
    bound: &BoundSorobanInputs<'_>,
    tool: &'static str,
    timing: WitnessTiming,
) -> Result<CrossCheckOutcome, WalletError> {
    let subject = soroban_subject(bound, context.network_passphrase())?;
    let prepared = match cross_check_requirement(
        context.chain_id,
        value,
        thresholds,
        profile.oracle_provider_url.is_some(),
        false,
    )? {
        CrossCheckRequirement::NotRequired => {
            if context.chain_id.is_mainnet() {
                let oracle = super::required_oracle(profile, context, tool)?;
                super::oracle_ledger_bound(&oracle, context, bound.inputs, timing, tool).await?;
            }
            return Ok(CrossCheckOutcome::NotRequired);
        }
        CrossCheckRequirement::Skipped(reason) => {
            warn_skipped(tool, reason);
            return Ok(CrossCheckOutcome::Skipped(reason));
        }
        CrossCheckRequirement::Required => SorobanCrossCheck::Required {
            oracle: super::required_oracle(profile, context, tool)?,
            context: context.clone(),
            tool,
        },
    };
    prepared
        .witness_with_subject(*bound.inputs, timing, Some(subject))
        .await
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test assertions"
    )]

    use std::time::Duration;

    use serde_json::json;
    use sha2::{Digest as _, Sha256};
    use stellar_agent_core::asset_id::CanonicalAsset;
    use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
    use stellar_agent_test_support::EchoIdResponder;
    use stellar_xdr::{
        AccountEntry, AccountEntryExt, AlphaNum4, AssetCode4, BeginSponsoringFutureReservesOp,
        ChangeTrustOp, ClaimClaimableBalanceOp, ContractId, CreateAccountOp, DecoratedSignature,
        Hash, InvokeContractArgs, InvokeHostFunctionOp, LedgerEntryData, LedgerKey,
        LedgerKeyAccount, Limits, Memo, PaymentOp, Preconditions, ScSymbol, ScVal, SequenceNumber,
        Signature, SignatureHint, SorobanAddressCredentials, SorobanAuthorizationEntry, Thresholds,
        Transaction, TransactionExt, TransactionV1Envelope, VecM, WriteXdr,
    };
    use wiremock::matchers::{body_partial_json, method};
    use wiremock::{Mock, MockServer};

    use super::super::inputs::{
        AccountObservation, ClaimWitnessInputs, ClaimableBalanceObservation,
        CreateAccountWitnessInputs, DestinationObservation, IssuerObservation, MemoObservation,
        PayWitnessInputs, PoolInitWitnessInputs, TrustlineObservation, TrustlineWitnessInputs,
    };
    use super::*;

    fn address(n: u8) -> String {
        strkey([n; 32])
    }

    fn muxed(n: u8) -> MuxedAccount {
        MuxedAccount::Ed25519(Uint256([n; 32]))
    }

    fn account_id(n: u8) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([n; 32])))
    }

    fn account(n: u8) -> AccountEntry {
        AccountEntry {
            account_id: account_id(n),
            balance: 100_000_000_000,
            seq_num: SequenceNumber(42),
            num_sub_entries: 2,
            inflation_dest: None,
            flags: 0,
            home_domain: b"example.org".to_vec().try_into().unwrap(),
            thresholds: Thresholds([1, 1, 1, 1]),
            signers: vec![].try_into().unwrap(),
            ext: AccountEntryExt::V0,
        }
    }

    fn source(n: u8) -> AccountObservation {
        AccountObservation::from_view(
            &crate::account::project_account_entry(&address(n), &account(n)).unwrap(),
        )
        .unwrap()
    }

    fn usdc() -> CanonicalAsset {
        CanonicalAsset::classic("USDC", &address(9)).unwrap()
    }

    fn op(body: OperationBody) -> Operation {
        Operation {
            source_account: None,
            body,
        }
    }

    fn payment(destination: u8, asset: XdrAsset) -> Operation {
        op(OperationBody::Payment(PaymentOp {
            destination: muxed(destination),
            asset,
            amount: 10,
        }))
    }

    fn usdc_xdr() -> XdrAsset {
        XdrAsset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"USDC"),
            issuer: account_id(9),
        })
    }

    fn create_account(destination: u8) -> Operation {
        create_account_with(destination, 10_000_000)
    }

    fn create_account_with(destination: u8, starting_balance: i64) -> Operation {
        op(OperationBody::CreateAccount(CreateAccountOp {
            destination: account_id(destination),
            starting_balance,
        }))
    }

    fn change_trust(issuer: u8) -> Operation {
        op(OperationBody::ChangeTrust(ChangeTrustOp {
            line: ChangeTrustAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"USDC"),
                issuer: account_id(issuer),
            }),
            limit: i64::MAX,
        }))
    }

    fn claim(balance: u8) -> Operation {
        op(OperationBody::ClaimClaimableBalance(
            ClaimClaimableBalanceOp {
                balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([balance; 32])),
            },
        ))
    }

    fn sponsored_channel(funder: u8, channel: u8) -> [Operation; 3] {
        [
            Operation {
                source_account: Some(muxed(funder)),
                body: OperationBody::BeginSponsoringFutureReserves(
                    BeginSponsoringFutureReservesOp {
                        sponsored_id: account_id(channel),
                    },
                ),
            },
            Operation {
                source_account: Some(muxed(funder)),
                body: OperationBody::CreateAccount(CreateAccountOp {
                    destination: account_id(channel),
                    starting_balance: 0,
                }),
            },
            Operation {
                source_account: Some(muxed(channel)),
                body: OperationBody::EndSponsoringFutureReserves,
            },
        ]
    }

    fn transaction(source: u8, sequence: i64, operations: Vec<Operation>) -> Transaction {
        Transaction {
            source_account: muxed(source),
            fee: 100,
            seq_num: SequenceNumber(sequence),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: operations.try_into().unwrap(),
            ext: TransactionExt::V0,
        }
    }

    fn envelope_of(tx: &Transaction, signed: bool) -> String {
        let signatures: Vec<DecoratedSignature> = if signed {
            vec![DecoratedSignature {
                hint: SignatureHint([1, 2, 3, 4]),
                signature: Signature(vec![7; 64].try_into().unwrap()),
            }]
        } else {
            vec![]
        };
        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: tx.clone(),
            signatures: signatures.try_into().unwrap(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap()
    }

    /// The network transaction hash computed from its definition:
    /// `SHA-256(network id || ENVELOPE_TYPE_TX || transaction XDR)`.
    fn expected_hash(tx: &Transaction) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(Sha256::digest(TESTNET_PASSPHRASE.as_bytes()));
        hasher.update(2u32.to_be_bytes());
        hasher.update(tx.to_xdr(Limits::none()).unwrap());
        hasher.finalize().into()
    }

    fn pay_inputs(trustline: bool) -> ClassicInputs {
        PayWitnessInputs {
            source: source(7),
            destination: DestinationObservation::from_view(&address(8), None),
            memo: MemoObservation::Read(false),
            trustline: trustline.then(|| TrustlineObservation {
                account_id: address(7),
                asset: usdc(),
                state: None,
            }),
        }
        .into()
    }

    fn trustline_inputs() -> ClassicInputs {
        TrustlineWitnessInputs {
            source: source(7),
            issuer: IssuerObservation::from_view(&address(9), None),
        }
        .into()
    }

    fn claim_inputs() -> ClassicInputs {
        ClaimWitnessInputs {
            source: source(7),
            trustline: None,
            balance: Some(ClaimableBalanceObservation {
                balance_id: [5; 32],
                entry: None,
            }),
        }
        .into()
    }

    fn pool_inputs() -> ClassicInputs {
        PoolInitWitnessInputs {
            funder: source(7),
            absent_channels: vec![address(11), address(12)],
        }
        .into()
    }

    /// Decodes `envelope_b64` and checks it as the bound producer does.
    fn subject_of(
        inputs: &ClassicInputs,
        envelope_b64: &str,
        network_passphrase: &str,
    ) -> Result<[u8; 32], WalletError> {
        classic_subject(
            inputs,
            &decode_classic_envelope(envelope_b64)?,
            network_passphrase,
        )
    }

    fn part(result: Result<[u8; 32], WalletError>) -> &'static str {
        match result {
            Err(WalletError::Network(NetworkError::WitnessUnavailable {
                reason: WitnessUnavailableReason::EnvelopeMismatch { part },
            })) => part,
            other => panic!("expected an envelope mismatch, got {other:?}"),
        }
    }

    #[test]
    fn the_classic_subject_is_the_network_transaction_hash_signed_or_not() {
        let tx = transaction(7, 43, vec![payment(8, XdrAsset::Native)]);
        let expected = expected_hash(&tx);
        for signed in [false, true] {
            let subject = subject_of(
                &pay_inputs(false),
                &envelope_of(&tx, signed),
                TESTNET_PASSPHRASE,
            )
            .unwrap();
            assert_eq!(subject, expected, "signed={signed}");
        }
    }

    #[test]
    fn every_input_kind_accepts_its_own_transaction() {
        let pool_ops: Vec<Operation> = sponsored_channel(7, 11)
            .into_iter()
            .chain(sponsored_channel(7, 12))
            .collect();
        let cases = [
            (pay_inputs(false), vec![payment(8, XdrAsset::Native)]),
            (pay_inputs(true), vec![payment(8, usdc_xdr())]),
            (
                CreateAccountWitnessInputs { source: source(7) }.into(),
                vec![create_account(8)],
            ),
            (trustline_inputs(), vec![change_trust(9)]),
            (claim_inputs(), vec![claim(5)]),
            (pool_inputs(), pool_ops),
        ];
        for (inputs, ops) in cases {
            let tx = transaction(7, 43, ops);
            assert_eq!(
                subject_of(&inputs, &envelope_of(&tx, false), TESTNET_PASSPHRASE).unwrap(),
                expected_hash(&tx)
            );
        }
    }

    #[test]
    fn the_source_and_the_sequence_must_be_the_observed_ones() {
        let inputs = pay_inputs(false);
        let ops = || vec![payment(8, XdrAsset::Native)];
        assert_eq!(
            part(subject_of(
                &inputs,
                &envelope_of(&transaction(6, 43, ops()), false),
                TESTNET_PASSPHRASE
            )),
            "source"
        );
        for sequence in [42, 44] {
            assert_eq!(
                part(subject_of(
                    &inputs,
                    &envelope_of(&transaction(7, sequence, ops()), false),
                    TESTNET_PASSPHRASE
                )),
                "sequence"
            );
        }
        assert_eq!(
            part(subject_of(&inputs, "not-xdr", TESTNET_PASSPHRASE)),
            "envelope"
        );
    }

    #[test]
    fn each_input_kind_refuses_another_operation() {
        let mut sourced = payment(8, XdrAsset::Native);
        sourced.source_account = Some(muxed(6));
        let mut missing_end: Vec<Operation> = sponsored_channel(7, 11).into_iter().collect();
        missing_end.extend(sponsored_channel(7, 12).into_iter().take(2));
        let mut wrong_end: Vec<Operation> = sponsored_channel(7, 11).into_iter().collect();
        wrong_end.extend(sponsored_channel(7, 12));
        wrong_end[5].source_account = Some(muxed(7));
        let cases: Vec<(&str, ClassicInputs, Vec<Operation>)> = vec![
            (
                "pay destination",
                pay_inputs(false),
                vec![payment(9, XdrAsset::Native)],
            ),
            ("pay asset", pay_inputs(false), vec![payment(8, usdc_xdr())]),
            (
                "pay native for an issued asset",
                pay_inputs(true),
                vec![payment(8, XdrAsset::Native)],
            ),
            ("pay operation", pay_inputs(false), vec![create_account(8)]),
            (
                "pay count",
                pay_inputs(false),
                vec![payment(8, XdrAsset::Native), payment(8, XdrAsset::Native)],
            ),
            ("pay operation source", pay_inputs(false), vec![sourced]),
            (
                "create operation",
                CreateAccountWitnessInputs { source: source(7) }.into(),
                vec![payment(8, XdrAsset::Native)],
            ),
            (
                "trustline issuer",
                trustline_inputs(),
                vec![change_trust(10)],
            ),
            ("trustline operation", trustline_inputs(), vec![claim(5)]),
            ("claim balance", claim_inputs(), vec![claim(6)]),
            ("claim operation", claim_inputs(), vec![change_trust(9)]),
            (
                "pool channel",
                pool_inputs(),
                sponsored_channel(7, 11)
                    .into_iter()
                    .chain(sponsored_channel(7, 13))
                    .collect(),
            ),
            ("pool count", pool_inputs(), missing_end),
            ("pool end source", pool_inputs(), wrong_end),
        ];
        for (name, inputs, ops) in cases {
            let tx = transaction(7, 43, ops);
            assert_eq!(
                part(subject_of(
                    &inputs,
                    &envelope_of(&tx, false),
                    TESTNET_PASSPHRASE
                )),
                "operation",
                "{name}"
            );
        }
    }

    fn testnet_profile(oracle: Option<&MockServer>) -> Profile {
        let builder = Profile::builder_testnet("signer", "witness", "nonce", "witness")
            .rpc_url("https://primary.example/rpc");
        match oracle {
            Some(server) => builder
                .oracle_provider_url(url::Url::parse(&format!("{}/oracle", server.uri())).unwrap())
                .build(),
            None => builder.build(),
        }
    }

    fn timing() -> WitnessTiming {
        WitnessTiming {
            attempt_budget: Duration::from_millis(300),
            retry_backoff: Duration::from_millis(1),
        }
    }

    /// The envelope check runs before the requirement rule: a value below the
    /// threshold needs no comparison, yet a mismatched envelope refuses.
    #[tokio::test]
    async fn the_envelope_check_precedes_the_requirement_rule() {
        let profile = testnet_profile(None);
        let context = NetworkContext::from_profile(&profile);
        let thresholds = ThresholdSet::from_profile(&profile);
        let native = CanonicalAsset::Native;
        let value = CrossCheckValue::Amount {
            asset: &native,
            base_units: 10_000_000,
        };
        let inputs: ClassicInputs = CreateAccountWitnessInputs { source: source(7) }.into();
        let good = envelope_of(&transaction(7, 43, vec![create_account(8)]), false);
        let bad = envelope_of(&transaction(7, 44, vec![create_account(8)]), false);
        let outcome = obtain_classic_witness_bound_with_timing(
            &profile,
            &context,
            value,
            inputs.clone(),
            &good,
            &thresholds,
            "test",
            timing(),
        )
        .await
        .unwrap();
        assert!(matches!(outcome, CrossCheckOutcome::NotRequired));
        let error = obtain_classic_witness_bound_with_timing(
            &profile,
            &context,
            value,
            inputs,
            &bad,
            &thresholds,
            "test",
            timing(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), "network.witness_unavailable");
        assert!(error.to_string().contains("sequence"), "{error}");
    }

    async fn classic_oracle() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "getNetwork"})))
            .respond_with(EchoIdResponder::new(
                stellar_agent_test_support::signed_envelope::get_network_result(TESTNET_PASSPHRASE),
            ))
            .mount(&server)
            .await;
        let key = LedgerKey::Account(LedgerKeyAccount {
            account_id: account_id(7),
        });
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "getLedgerEntries"})))
            .respond_with(EchoIdResponder::new(json!({
                "entries": [{
                    "key": key.to_xdr_base64(Limits::none()).unwrap(),
                    "xdr": LedgerEntryData::Account(account(7))
                        .to_xdr_base64(Limits::none())
                        .unwrap(),
                    "lastModifiedLedgerSeq": 100,
                }],
                "latestLedger": 100,
            })))
            .mount(&server)
            .await;
        server
    }

    /// A passed bound witness carries the envelope's transaction hash; the
    /// unbound producer's carries none.
    ///
    /// The account creation funds exactly the effective native threshold, the
    /// profile value raised to the floor, so the comparison is required.
    #[tokio::test]
    async fn a_passed_classic_witness_carries_its_subject() {
        let server = classic_oracle().await;
        let profile = testnet_profile(Some(&server));
        let context = NetworkContext::from_profile(&profile);
        let thresholds = ThresholdSet::from_profile(&profile);
        let threshold = thresholds.native_stroops;
        let tx = transaction(
            7,
            43,
            vec![create_account_with(8, i64::try_from(threshold).unwrap())],
        );
        let inputs: ClassicInputs = CreateAccountWitnessInputs { source: source(7) }.into();
        let value = CrossCheckValue::Amount {
            asset: &CanonicalAsset::Native,
            base_units: i128::from(threshold),
        };
        let bound = obtain_classic_witness_bound_with_timing(
            &profile,
            &context,
            value,
            inputs.clone(),
            &envelope_of(&tx, false),
            &thresholds,
            "test",
            timing(),
        )
        .await
        .unwrap();
        let CrossCheckOutcome::Passed(witness) = bound else {
            panic!("expected a passed witness, got {bound:?}");
        };
        assert_eq!(witness.subject(), Some(expected_hash(&tx)));

        let unbound = super::super::obtain_classic_witness_with_timing(
            &profile,
            &context,
            value,
            inputs,
            "test",
            timing(),
        )
        .await
        .unwrap();
        let CrossCheckOutcome::Passed(witness) = unbound else {
            panic!("expected a passed witness, got {unbound:?}");
        };
        assert_eq!(witness.subject(), None);
    }

    // ── Soroban ─────────────────────────────────────────────────────────

    const NATIVE_SAC: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

    fn sc_account(n: u8) -> ScAddress {
        ScAddress::Account(account_id(n))
    }

    fn transfer(amount: i128) -> InvokeContractArgs {
        let contract = stellar_strkey::Contract::from_string(NATIVE_SAC).unwrap();
        InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash(contract.0))),
            function_name: ScSymbol("transfer".try_into().unwrap()),
            args: vec![
                ScVal::Address(sc_account(5)),
                ScVal::Address(sc_account(6)),
                ScVal::from(amount),
            ]
            .try_into()
            .unwrap(),
        }
    }

    fn root(amount: i128) -> SorobanAuthorizedInvocation {
        SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(transfer(amount)),
            sub_invocations: VecM::default(),
        }
    }

    fn auth_entry(payer: u8, amount: i128) -> SorobanAuthorizationEntry {
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: sc_account(payer),
                nonce: 7,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: root(amount),
        }
    }

    fn soroban_envelope(amount: i128) -> TransactionEnvelope {
        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: transaction(
                0,
                0,
                vec![op(OperationBody::InvokeHostFunction(
                    InvokeHostFunctionOp {
                        host_function: HostFunction::InvokeContract(transfer(amount)),
                        auth: VecM::default(),
                    },
                ))],
            ),
            signatures: VecM::default(),
        })
    }

    fn simulation(auth: &[SorobanAuthorizationEntry]) -> serde_json::Value {
        let auth: Vec<String> = auth
            .iter()
            .map(|entry| entry.to_xdr_base64(Limits::none()).unwrap())
            .collect();
        json!({
            "transactionData": "AAAA",
            "minResourceFee": "1000",
            "results": [{
                "auth": auth,
                "xdr": ScVal::Void.to_xdr_base64(Limits::none()).unwrap(),
            }],
            "latestLedger": 1000,
        })
    }

    fn primary(
        auth: &[SorobanAuthorizationEntry],
    ) -> stellar_rpc_client::SimulateTransactionResponse {
        serde_json::from_value(simulation(auth)).unwrap()
    }

    /// The Soroban intent digest computed from its definition.
    fn expected_intent(root: &SorobanAuthorizedInvocation) -> [u8; 32] {
        let xdr = root.to_xdr(Limits::none()).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(b"stellar-agent-soroban-intent:v1");
        hasher.update(Sha256::digest(TESTNET_PASSPHRASE.as_bytes()));
        hasher.update(u32::try_from(xdr.len()).unwrap().to_be_bytes());
        hasher.update(&xdr);
        hasher.finalize().into()
    }

    fn soroban_part(
        envelope: &TransactionEnvelope,
        primary: &stellar_rpc_client::SimulateTransactionResponse,
        expected_root: &SorobanAuthorizedInvocation,
        payer: &str,
    ) -> Result<[u8; 32], WalletError> {
        let inputs = SorobanWitnessInputs {
            envelope,
            primary,
            expiration_ledger: 1060,
            resource_fee_ceiling: 10_000_000,
        };
        soroban_subject(
            &BoundSorobanInputs {
                inputs: &inputs,
                expected_root,
                payer,
            },
            TESTNET_PASSPHRASE,
        )
    }

    #[test]
    fn the_soroban_subject_is_the_intent_digest_of_the_expected_root() {
        let envelope = soroban_envelope(10);
        let primary = primary(&[auth_entry(5, 10)]);
        assert_eq!(
            soroban_part(&envelope, &primary, &root(10), &address(5)).unwrap(),
            expected_intent(&root(10))
        );
    }

    #[test]
    fn the_soroban_check_refuses_another_payer_root_or_call() {
        let envelope = soroban_envelope(10);
        let good = primary(&[auth_entry(5, 10)]);
        assert_eq!(
            part(soroban_part(&envelope, &good, &root(10), &address(6))),
            "authorization"
        );
        assert_eq!(
            part(soroban_part(&envelope, &good, &root(11), &address(5))),
            "authorization"
        );
        let two = primary(&[auth_entry(5, 10), auth_entry(5, 10)]);
        assert_eq!(
            part(soroban_part(&envelope, &two, &root(10), &address(5))),
            "authorization"
        );
        assert_eq!(
            part(soroban_part(
                &soroban_envelope(11),
                &good,
                &root(10),
                &address(5)
            )),
            "operation"
        );
    }

    /// A passed bound Soroban witness carries the intent digest.
    #[tokio::test]
    async fn a_passed_soroban_witness_carries_its_subject() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "getNetwork"})))
            .respond_with(EchoIdResponder::new(
                stellar_agent_test_support::signed_envelope::get_network_result(TESTNET_PASSPHRASE),
            ))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "simulateTransaction"})))
            .respond_with(EchoIdResponder::new(simulation(&[auth_entry(5, 10)])))
            .mount(&server)
            .await;
        let profile = testnet_profile(Some(&server));
        let context = NetworkContext::from_profile(&profile);
        let thresholds = ThresholdSet::from_profile(&profile);
        let envelope = soroban_envelope(10);
        let primary = primary(&[auth_entry(5, 10)]);
        let inputs = SorobanWitnessInputs {
            envelope: &envelope,
            primary: &primary,
            expiration_ledger: 1060,
            resource_fee_ceiling: 10_000_000,
        };
        let expected_root = root(10);
        let payer = address(5);
        let outcome = obtain_soroban_witness_bound_with_timing(
            &profile,
            &context,
            CrossCheckValue::Unvalued,
            &thresholds,
            &BoundSorobanInputs {
                inputs: &inputs,
                expected_root: &expected_root,
                payer: &payer,
            },
            "test",
            timing(),
        )
        .await
        .unwrap();
        let CrossCheckOutcome::Passed(witness) = outcome else {
            panic!("expected a passed witness, got {outcome:?}");
        };
        assert_eq!(witness.subject(), Some(expected_intent(&expected_root)));
    }

    #[test]
    fn the_witness_fact_digest_is_frozen() {
        let witness = super::super::CrossCheckWitness::for_crate_tests(
            "https://oracle.example:8443",
            4_242,
            [3; 32],
            vec![stellar_agent_core::cross_check::WitnessEntry::SourceAccount],
        );
        assert_eq!(
            stellar_agent_core::hex::encode(&witness.fact_digest()),
            "ffe3aa935fa9b02b92a28ab0aeb86318111cef297565cb12b60bf8238ea92e0f"
        );
    }

    #[test]
    fn memo_observation_matches_the_envelope_and_destination() {
        let mut tx = transaction(7, 43, vec![payment(8, XdrAsset::Native)]);
        let mut inputs = pay_inputs(false);
        assert!(subject_of(&inputs, &envelope_of(&tx, false), TESTNET_PASSPHRASE).is_ok());
        let ClassicInputs::Pay(v) = &mut inputs else {
            unreachable!()
        };
        v.memo = MemoObservation::NotRead;
        assert_eq!(
            part(subject_of(
                &inputs,
                &envelope_of(&tx, false),
                TESTNET_PASSPHRASE
            )),
            "memo"
        );
        tx.memo = Memo::Id(1);
        assert!(subject_of(&inputs, &envelope_of(&tx, false), TESTNET_PASSPHRASE).is_ok());
        let read = pay_inputs(false);
        assert_eq!(
            part(subject_of(
                &read,
                &envelope_of(&tx, false),
                TESTNET_PASSPHRASE
            )),
            "memo"
        );
        tx.memo = Memo::None;
        let mut payment = payment(8, XdrAsset::Native);
        let OperationBody::Payment(op) = &mut payment.body else {
            unreachable!()
        };
        op.destination = MuxedAccount::MuxedEd25519(stellar_xdr::MuxedAccountMed25519 {
            id: 7,
            ed25519: Uint256([8; 32]),
        });
        tx.operations = vec![payment].try_into().unwrap();
        assert!(subject_of(&inputs, &envelope_of(&tx, false), TESTNET_PASSPHRASE).is_ok());
        assert_eq!(
            part(subject_of(
                &read,
                &envelope_of(&tx, false),
                TESTNET_PASSPHRASE
            )),
            "memo"
        );
    }

    #[tokio::test]
    async fn the_bound_producer_compares_payment_and_creation_values() {
        let profile = testnet_profile(None);
        let context = NetworkContext::from_profile(&profile);
        let thresholds = ThresholdSet::from_profile(&profile);
        for (inputs, op, amount) in [
            (pay_inputs(false), payment(8, XdrAsset::Native), 10),
            (
                CreateAccountWitnessInputs { source: source(7) }.into(),
                create_account(8),
                10_000_000,
            ),
        ] {
            let envelope = envelope_of(&transaction(7, 43, vec![op]), false);
            for (asset, base_units) in [
                (&CanonicalAsset::Native, amount - 1),
                (&CanonicalAsset::Native, amount + 1),
                (&usdc(), amount),
            ] {
                let error = obtain_classic_witness_bound(
                    &profile,
                    &context,
                    CrossCheckValue::Amount { asset, base_units },
                    inputs.clone(),
                    &envelope,
                    &thresholds,
                    "test",
                )
                .await
                .unwrap_err();
                assert!(matches!(
                    error,
                    WalletError::Network(NetworkError::WitnessUnavailable {
                        reason: WitnessUnavailableReason::EnvelopeMismatch { part: "value" }
                    })
                ));
            }
            assert!(
                obtain_classic_witness_bound(
                    &profile,
                    &context,
                    CrossCheckValue::Amount {
                        asset: &CanonicalAsset::Native,
                        base_units: amount
                    },
                    inputs,
                    &envelope,
                    &thresholds,
                    "test"
                )
                .await
                .is_ok()
            );
        }
    }

    #[test]
    fn every_classic_operation_source_is_bound() {
        let cases = [
            (
                CreateAccountWitnessInputs { source: source(7) }.into(),
                vec![create_account(8)],
                0,
            ),
            (trustline_inputs(), vec![change_trust(9)], 0),
            (claim_inputs(), vec![claim(5)], 0),
            (
                pool_inputs(),
                [sponsored_channel(7, 11), sponsored_channel(7, 12)].concat(),
                0,
            ),
            (
                pool_inputs(),
                [sponsored_channel(7, 11), sponsored_channel(7, 12)].concat(),
                1,
            ),
        ];
        for (inputs, mut ops, index) in cases {
            assert!(check_operations(&inputs, &ops, &address(7)).is_ok());
            ops[index].source_account = Some(muxed(6));
            assert!(check_operations(&inputs, &ops, &address(7)).is_err());
        }
    }

    #[test]
    fn pool_channels_are_bound_independently_and_require_an_operation() {
        let inputs = pool_inputs();
        for index in [0, 1] {
            let mut ops = [sponsored_channel(7, 11), sponsored_channel(7, 12)].concat();
            assert!(check_operations(&inputs, &ops, &address(7)).is_ok());
            ops[index] = sponsored_channel(7, 9)[index].clone();
            assert!(check_operations(&inputs, &ops, &address(7)).is_err());
        }
        let mut inputs = inputs;
        let ClassicInputs::PoolInit(v) = &mut inputs else {
            unreachable!()
        };
        v.absent_channels.clear();
        assert!(check_operations(&inputs, &[], &address(7)).is_err());
    }

    #[tokio::test]
    async fn soroban_identity_refuses_before_the_requirement_decision() {
        let profile = testnet_profile(None);
        let context = NetworkContext::from_profile(&profile);
        let thresholds = ThresholdSet::from_profile(&profile);
        let envelope = soroban_envelope(10);
        let primary = primary(&[auth_entry(5, 10)]);
        let inputs = SorobanWitnessInputs {
            envelope: &envelope,
            primary: &primary,
            expiration_ledger: 1060,
            resource_fee_ceiling: 10_000_000,
        };
        let root = root(10);
        for payer in [address(5), address(6)] {
            let result = obtain_soroban_witness_bound(
                &profile,
                &context,
                CrossCheckValue::Amount {
                    asset: &CanonicalAsset::Native,
                    base_units: 1,
                },
                &thresholds,
                &BoundSorobanInputs {
                    inputs: &inputs,
                    expected_root: &root,
                    payer: &payer,
                },
                "test",
            )
            .await;
            if payer == address(5) {
                assert!(matches!(result.unwrap(), CrossCheckOutcome::NotRequired));
            } else {
                assert!(matches!(
                    result.unwrap_err(),
                    WalletError::Network(NetworkError::WitnessUnavailable {
                        reason: WitnessUnavailableReason::EnvelopeMismatch {
                            part: "authorization"
                        }
                    })
                ));
            }
        }
    }

    #[test]
    fn soroban_source_account_credentials_refuse() {
        let envelope = soroban_envelope(10);
        let mut entry = auth_entry(5, 10);
        let good = primary(&[entry.clone()]);
        assert!(soroban_part(&envelope, &good, &root(10), &address(5)).is_ok());
        entry.credentials = SorobanCredentials::SourceAccount;
        let bad = primary(&[entry]);
        assert_eq!(
            part(soroban_part(&envelope, &bad, &root(10), &address(5))),
            "authorization"
        );
    }
}
