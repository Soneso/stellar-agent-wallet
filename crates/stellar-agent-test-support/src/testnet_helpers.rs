//! Shared helpers for live testnet acceptance tests.
//!
//! This module is gated behind the `testnet-helpers` feature because it pulls
//! live-network and Soroban dependencies that default `stellar-agent-test-support`
//! users do not need.  It deliberately avoids depending on wallet crates that
//! already use test-support in their own tests; callers provide those operations
//! through small async closures.

#![allow(
    clippy::print_stderr,
    reason = "live acceptance helpers intentionally report redacted progress to stderr"
)]

use std::{error::Error, fmt, future::Future, time::Duration};

use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore as _};
use sha2::{Digest as _, Sha256};
use stellar_baselib::{
    account::{Account as BaselibAccount, AccountBehavior},
    asset::{Asset as BaselibAsset, AssetBehavior},
    claimant::{Claimant, ClaimantBehavior},
    operation::Operation as BaselibOperation,
    transaction::{Transaction, TransactionBehavior},
    transaction_builder::{TransactionBuilder, TransactionBuilderBehavior},
    xdr::{
        AccountId, BytesM, ClaimPredicate, ContractExecutable, ContractId, ContractIdPreimage,
        ContractIdPreimageFromAddress, CreateContractArgsV2, Hash, HashIdPreimage,
        HashIdPreimageContractId, HashIdPreimageOperationId, HostFunction, InvokeContractArgs,
        InvokeHostFunctionOp, LedgerKey, LedgerKeyContractCode, Limits, Operation, OperationBody,
        PublicKey, ScAddress, ScBytes, ScSymbol, ScVal, SequenceNumber, SorobanAuthorizationEntry,
        SorobanCredentials, SorobanTransactionData, Uint256, VecM, WriteXdr,
    },
};
use stellar_rpc_client::Client;
use zeroize::Zeroizing;

const BASE_FEE: u32 = 100;

/// Number of attempts for the `retry_rpc!` macro.
///
/// Exposed so acceptance tests can reference the same constant when building
/// log messages or assertions.
pub const RETRY_RPC_ATTEMPTS: u32 = 3;

/// Backoff duration in milliseconds between `retry_rpc!` attempts.
///
/// Exposed so acceptance tests can reference the same constant when building
/// log messages or assertions.
pub const RETRY_RPC_BACKOFF_MS: u64 = 2_000;

/// Error type used by live testnet helper plumbing.
#[derive(Debug)]
pub struct TestnetHelperError {
    message: String,
}

impl TestnetHelperError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for TestnetHelperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for TestnetHelperError {}

/// Result alias for live testnet helper functions.
pub type TestnetHelperResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

/// Deployment inputs generated and funded by [`deploy_funded_smart_account`].
pub struct DeploySmartAccountRequest<S> {
    /// Test-specific environment variable label used by the deploy path.
    pub keypair_var_name: String,
    /// Initial signer G-strkey to install in the smart account.
    pub initial_signer: String,
    /// Deployer G-strkey funded by Friendbot.
    pub deployer_g_strkey: String,
    /// Deployer signer material in the caller's signer type.
    pub deployer_signer: S,
    /// Random deployment salt.
    pub salt: [u8; 32],
    /// Network passphrase to pass through to the deploy path.
    pub network_passphrase: String,
    /// RPC URL to pass through to the deploy path.
    pub rpc_url: String,
    /// Timeout matching the existing live acceptance tests.
    pub timeout: Duration,
    /// Explicit deployment fee per operation in stroops.
    pub fee_per_op_stroops: u32,
}

/// Minimal deployment output consumed by the shared helper.
pub struct DeploySmartAccountOutcome {
    /// The deployed smart-account C-strkey.
    pub smart_account: String,
    /// The deployment transaction hash, when the deploy path returned one.
    pub tx_hash: Option<String>,
}

/// A freshly deployed smart account and its initial signer.
pub struct DeployedSmartAccount<S> {
    /// The deployed smart-account C-strkey.
    pub wallet_c: String,
    /// The G-strkey for the signer installed as the initial smart-account signer.
    pub signer_g_strkey: String,
    /// The software signer corresponding to [`Self::signer_g_strkey`].
    pub signer: S,
    /// The deployment transaction hash, when the deploy path returned one.
    pub deploy_tx_hash: Option<String>,
}

/// Redacts a Stellar strkey to first-5-last-5 for acceptance-test output.
#[must_use]
pub fn redact_strkey(s: &str) -> String {
    if s.len() > 10 {
        format!("{}...{}", &s[..5], &s[s.len() - 5..])
    } else {
        "[short]".to_owned()
    }
}

/// Redacts a transaction hash to first-8-last-8 for acceptance-test output.
#[must_use]
pub fn redact_hash(h: &str) -> String {
    if h.len() > 16 {
        format!("{}...{}", &h[..8], &h[h.len() - 8..])
    } else {
        "[short]".to_owned()
    }
}

/// Retries an async RPC operation with the acceptance-test retry cadence.
///
/// Attempts [`RETRY_RPC_ATTEMPTS`] times with [`RETRY_RPC_BACKOFF_MS`] ms
/// between retries.  This macro is intended for `testnet-helpers` consumers
/// only; it must not be used in production code paths.
#[macro_export]
macro_rules! retry_rpc {
    ($expr:expr) => {{
        let mut attempt = 0u32;
        loop {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(
                    $crate::testnet_helpers::RETRY_RPC_BACKOFF_MS,
                ))
                .await;
            }
            match $expr.await {
                Ok(v) => break Ok(v),
                Err(e) => {
                    eprintln!(
                        "RPC attempt {}/{}: {:?}",
                        attempt + 1,
                        $crate::testnet_helpers::RETRY_RPC_ATTEMPTS,
                        e
                    );
                    if attempt + 1 == $crate::testnet_helpers::RETRY_RPC_ATTEMPTS {
                        break Err(e);
                    }
                    attempt += 1;
                }
            }
        }
    }};
}

/// Deploys a fresh smart account with a fresh software signer on testnet.
///
/// The signer G-account and deployer G-account are both Friendbot-funded before
/// deployment, matching the c10 pattern used by the live acceptance tests.
///
/// # Errors
///
/// Returns an error when Friendbot refuses either funding request or when the
/// caller-provided deployment operation fails.
pub async fn deploy_funded_smart_account<S, M, D, Fut>(
    log_prefix: &str,
    keypair_var_name: &str,
    rpc_url: &str,
    network_passphrase: &str,
    friendbot_url: &str,
    make_signer: M,
    deploy: D,
) -> TestnetHelperResult<DeployedSmartAccount<S>>
where
    S: Send + 'static,
    M: Fn(Zeroizing<[u8; 32]>) -> S,
    D: FnOnce(DeploySmartAccountRequest<S>) -> Fut,
    Fut: Future<Output = TestnetHelperResult<DeploySmartAccountOutcome>>,
{
    eprintln!("{log_prefix} Step 1: generating fresh ed25519 signer");
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let signer_g_strkey = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
    );
    let signer_seed: Zeroizing<[u8; 32]> = Zeroizing::new(signing_key.to_bytes());
    let signer = make_signer(signer_seed);
    eprintln!(
        "{log_prefix} fresh signer: {}",
        redact_strkey(&signer_g_strkey)
    );

    fund_with_friendbot(friendbot_url, rpc_url, &signer_g_strkey, "signer G-account").await?;
    eprintln!(
        "{log_prefix} signer G-account funded: {}",
        redact_strkey(&signer_g_strkey)
    );

    eprintln!("{log_prefix} Step 2: deploying fresh smart-account");
    let deployer_sk = SigningKey::generate(&mut OsRng);
    let deployer_vk = deployer_sk.verifying_key();
    let deployer_g_strkey = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(deployer_vk.to_bytes())
    );
    let deployer_seed: Zeroizing<[u8; 32]> = Zeroizing::new(deployer_sk.to_bytes());
    let deployer_signer = make_signer(deployer_seed);

    fund_with_friendbot(friendbot_url, rpc_url, &deployer_g_strkey, "deployer").await?;
    eprintln!(
        "{log_prefix} deployer funded: {}",
        redact_strkey(&deployer_g_strkey)
    );

    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    let deploy_result = deploy(DeploySmartAccountRequest {
        keypair_var_name: keypair_var_name.to_owned(),
        initial_signer: signer_g_strkey.clone(),
        deployer_g_strkey,
        deployer_signer,
        salt,
        network_passphrase: network_passphrase.to_owned(),
        rpc_url: rpc_url.to_owned(),
        timeout: Duration::from_secs(120),
        fee_per_op_stroops: 1_000_000,
    })
    .await?;

    eprintln!(
        "{log_prefix} smart-account deployed: {}",
        redact_strkey(&deploy_result.smart_account)
    );
    if let Some(ref tx) = deploy_result.tx_hash {
        eprintln!("{log_prefix} deploy tx: {}", redact_hash(tx));
    }

    Ok(DeployedSmartAccount {
        wallet_c: deploy_result.smart_account,
        signer_g_strkey,
        signer,
        deploy_tx_hash: deploy_result.tx_hash,
    })
}

/// Funds a smart-account C-address by transferring SAC balance from a fresh
/// Friendbot-funded G-account.
///
/// This is the eight-step XLM-SAC flow used by the on-chain acceptance tests:
/// build invoke args, simulate, re-simulate with returned source-account auth
/// entries, build the final envelope with resource fee, sign, submit, and
/// confirm.
///
/// # Errors
///
/// Returns an error when Friendbot funding, RPC fetch/simulate, XDR conversion,
/// signing, or submission fails.
#[allow(
    clippy::too_many_arguments,
    reason = "acceptance helper keeps test-specific network hooks explicit at call sites"
)]
pub async fn fund_sac_balance<R, B, BE, F, FFut, S, SFut, Sub, SubFut>(
    log_prefix: &str,
    rpc_url: &str,
    network_passphrase: &str,
    friendbot_url: &str,
    sac_contract: &str,
    to_c_address: &str,
    amount: i128,
    build_sac_transfer_invoke: B,
    fetch_sequence: F,
    sign_envelope: S,
    submit_signed_xdr: Sub,
) -> TestnetHelperResult<R>
where
    B: FnOnce(&str, &str, &str, i128) -> Result<InvokeContractArgs, BE>,
    BE: Error + Send + Sync + 'static,
    F: Fn(&str) -> FFut,
    FFut: Future<Output = TestnetHelperResult<i64>>,
    S: FnOnce(String, Zeroizing<[u8; 32]>, &str) -> SFut,
    SFut: Future<Output = TestnetHelperResult<String>>,
    Sub: Fn(String) -> SubFut,
    SubFut: Future<Output = TestnetHelperResult<R>>,
{
    eprintln!("{log_prefix} funding smart-account with SAC balance");

    let funder_sk = SigningKey::generate(&mut OsRng);
    let funder_vk = funder_sk.verifying_key();
    let funder_g = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(funder_vk.to_bytes())
    );
    let funder_seed: Zeroizing<[u8; 32]> = Zeroizing::new(funder_sk.to_bytes());

    fund_with_friendbot(friendbot_url, rpc_url, &funder_g, "funder G-account").await?;
    eprintln!(
        "{log_prefix} funder G-account funded: {}",
        redact_strkey(&funder_g)
    );

    let sac_invoke_args = build_sac_transfer_invoke(sac_contract, &funder_g, to_c_address, amount)?;

    // Client::new defaults to a 30-second timeout, matching the acceptance-test RPC timeout requirement.
    let client = Client::new(rpc_url).map_err(|e| TestnetHelperError::new(e.to_string()))?;

    let op_no_auth = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(sac_invoke_args.clone()),
            auth: VecM::default(),
        }),
    };

    let source_sequence = retry_rpc!(fetch_sequence(&funder_g))?;
    let mut source_acct = BaselibAccount::new(&funder_g, &source_sequence.to_string())
        .map_err(|e| TestnetHelperError::new(e.to_string()))?;

    let mut tx_builder = TransactionBuilder::new(&mut source_acct, network_passphrase, None);
    tx_builder.fee(BASE_FEE);
    tx_builder.add_operation(op_no_auth);
    let tx_for_simulate = tx_builder.build_for_simulation();

    // stellar-baselib 0.6.0 re-exports the workspace stellar_xdr directly, so
    // to_envelope() returns a stellar_xdr::TransactionEnvelope — no bridge needed.
    let sim_envelope = tx_for_simulate
        .to_envelope()
        .map_err(|e| TestnetHelperError::new(e.to_string()))?;
    let sim_resp = retry_rpc!(client.simulate_transaction_envelope(&sim_envelope, None))
        .map_err(|e| TestnetHelperError::new(e.to_string()))?;

    if let Some(err) = sim_resp.error {
        return Err(Box::new(TestnetHelperError::new(format!(
            "SAC transfer simulate returned error: {err}"
        ))));
    }
    // min_resource_fee is u64 in rpc-client 28 (deserialised from the JSON number-as-string
    // field, defaulting to 0 when absent).  A value of 0 means the simulate response did not
    // return resource fee information.
    if sim_resp.min_resource_fee == 0 {
        return Err(Box::new(TestnetHelperError::new(
            "SAC transfer first simulate did not return min_resource_fee",
        )));
    }

    // results()[0].auth contains the SorobanAuthorizationEntry values returned by the RPC.
    // stellar-baselib 0.6.0 uses the same stellar_xdr as the workspace, so these entries
    // can be embedded directly into the baselib Operation without a type bridge.
    let sim_results = sim_resp
        .results()
        .map_err(|e| TestnetHelperError::new(e.to_string()))?;
    let first_result = sim_results
        .into_iter()
        .next()
        .ok_or_else(|| TestnetHelperError::new("SAC transfer simulate result missing"))?;

    let auth_entries = first_result.auth;
    let has_address_creds = auth_entries
        .iter()
        .any(|e| matches!(&e.credentials, SorobanCredentials::Address(_)));
    if has_address_creds {
        return Err(Box::new(TestnetHelperError::new(
            "unexpected Address-credentialled auth entries in G-key SAC transfer simulate",
        )));
    }

    let source_account_vecm: VecM<SorobanAuthorizationEntry> = auth_entries
        .clone()
        .try_into()
        .map_err(|_| TestnetHelperError::new("auth entries VecM construction failed"))?;

    let resim_op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(sac_invoke_args.clone()),
            auth: source_account_vecm.clone(),
        }),
    };

    let source_sequence2 = retry_rpc!(fetch_sequence(&funder_g))?;
    let mut source_acct2 = BaselibAccount::new(&funder_g, &source_sequence2.to_string())
        .map_err(|e| TestnetHelperError::new(e.to_string()))?;

    let mut resim_builder = TransactionBuilder::new(&mut source_acct2, network_passphrase, None);
    resim_builder.fee(BASE_FEE);
    resim_builder.add_operation(resim_op);
    let resim_tx = resim_builder.build_for_simulation();

    let resim_envelope = resim_tx
        .to_envelope()
        .map_err(|e| TestnetHelperError::new(e.to_string()))?;
    let resim_resp = retry_rpc!(client.simulate_transaction_envelope(&resim_envelope, None))
        .map_err(|e| TestnetHelperError::new(e.to_string()))?;

    if let Some(err) = resim_resp.error {
        return Err(Box::new(TestnetHelperError::new(format!(
            "SAC transfer re-simulate returned error: {err}"
        ))));
    }

    let resource_fee = u32::try_from(resim_resp.min_resource_fee).map_err(|_| {
        TestnetHelperError::new(format!(
            "min_resource_fee {} overflows u32",
            resim_resp.min_resource_fee
        ))
    })?;

    // SorobanTransactionData from the re-simulate response is the same type as
    // stellar_baselib::xdr::SorobanTransactionData (both are workspace stellar_xdr types).
    let transaction_data = resim_resp
        .transaction_data()
        .map_err(|e| TestnetHelperError::new(e.to_string()))?;

    let final_op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(sac_invoke_args),
            auth: source_account_vecm,
        }),
    };

    let source_sequence3 = retry_rpc!(fetch_sequence(&funder_g))?;
    let mut source_acct3 = BaselibAccount::new(&funder_g, &source_sequence3.to_string())
        .map_err(|e| TestnetHelperError::new(e.to_string()))?;

    let mut final_builder = TransactionBuilder::new(&mut source_acct3, network_passphrase, None);
    final_builder.fee(BASE_FEE.saturating_add(resource_fee));
    final_builder.add_operation(final_op);
    let mut final_tx = final_builder.build_for_simulation();

    final_tx.soroban_data = Some(transaction_data);

    let final_envelope = final_tx
        .to_envelope()
        .map_err(|e| TestnetHelperError::new(format!("SAC transfer envelope build failed: {e}")))?;

    // Serialise to base64; the wallet signer operates on base64 XDR strings.
    let unsigned_xdr = final_envelope
        .to_xdr_base64(Limits::none())
        .map_err(|e| TestnetHelperError::new(format!("envelope XDR base64 encode failed: {e}")))?;
    let signed_xdr = sign_envelope(unsigned_xdr, funder_seed, network_passphrase).await?;

    let result = retry_rpc!(submit_signed_xdr(signed_xdr.clone()))?;
    eprintln!("{log_prefix} SAC funding confirmed on-chain");

    Ok(result)
}

/// Builds, signs, and submits a `CreateClaimableBalance` transaction for the
/// native asset with a single claimant, then derives the created balance's
/// canonical 72-hex id per CAP-23 (`HashIdPreimage::OpId`).
///
/// Production code has no balance-creation path (`ClassicOpBuilder` only
/// builds `ClaimClaimableBalance` — creating balances is not a wallet verb),
/// so the envelope here is built directly with `stellar-baselib`.
///
/// Callers inject `fetch_sequence`, `sign_envelope`, and `submit_signed_xdr`
/// rather than this module depending directly on `stellar-agent-network` —
/// the same dependency-injection style [`fund_sac_balance`] uses, avoiding a
/// dependency edge back onto a crate that already depends on
/// `stellar-agent-test-support` in its own tests.
///
/// # Errors
///
/// Returns an error when the sequence fetch, envelope construction, signing,
/// or submission fails.
#[allow(
    clippy::too_many_arguments,
    reason = "acceptance helper keeps test-specific network hooks explicit at call sites"
)]
pub async fn create_claimable_balance<F, FFut, S, SFut, Sub, SubFut>(
    creator_g: &str,
    creator_seed: &Zeroizing<[u8; 32]>,
    claimant_g: &str,
    amount_stroops: i64,
    predicate: Option<ClaimPredicate>,
    network_passphrase: &str,
    fee_per_op_stroops: u32,
    fetch_sequence: F,
    sign_envelope: S,
    submit_signed_xdr: Sub,
) -> TestnetHelperResult<String>
where
    F: Fn(&str) -> FFut,
    FFut: Future<Output = TestnetHelperResult<i64>>,
    S: FnOnce(String, Zeroizing<[u8; 32]>, &str) -> SFut,
    SFut: Future<Output = TestnetHelperResult<String>>,
    Sub: FnOnce(String) -> SubFut,
    SubFut: Future<Output = TestnetHelperResult<()>>,
{
    let creator_sequence = fetch_sequence(creator_g).await?;

    let seq_str = creator_sequence.to_string();
    let mut account = BaselibAccount::new(creator_g, &seq_str)
        .map_err(|e| TestnetHelperError::new(e.to_string()))?;
    let mut tx_builder = TransactionBuilder::new(&mut account, network_passphrase, None);
    tx_builder.fee(fee_per_op_stroops);

    let claimant = Claimant::new(Some(claimant_g), predicate)
        .map_err(|e| TestnetHelperError::new(e.to_string()))?;
    let op = BaselibOperation::new()
        .create_claimable_balance(&BaselibAsset::native(), amount_stroops, vec![claimant])
        .map_err(|e| TestnetHelperError::new(format!("{e:?}")))?;
    tx_builder.add_operation(op);

    let tx: Transaction = tx_builder.build();
    let envelope = tx
        .to_envelope()
        .map_err(|e| TestnetHelperError::new(e.to_string()))?;
    let unsigned_b64 = envelope
        .to_xdr_base64(Limits::none())
        .map_err(|e| TestnetHelperError::new(e.to_string()))?;

    let creator_seed_owned = Zeroizing::new(**creator_seed);
    let signed_b64 = sign_envelope(unsigned_b64, creator_seed_owned, network_passphrase).await?;

    submit_signed_xdr(signed_b64).await?;

    // CAP-23 balance-id derivation: SHA-256 of the HashIdPreimage::OpId
    // preimage built from the creator's account id, the tx's seq_num (the
    // fetched sequence + 1 — `TransactionBuilder::build` increments the
    // in-memory `Account` before rendering XDR), and the operation index
    // (0 — a single-operation transaction).
    let creator_pubkey = stellar_strkey::ed25519::PublicKey::from_string(creator_g)
        .map_err(|e| TestnetHelperError::new(e.to_string()))?
        .0;
    let creator_account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(creator_pubkey)));
    let tx_seq_num = creator_sequence.saturating_add(1);
    let preimage = HashIdPreimage::OpId(HashIdPreimageOperationId {
        source_account: creator_account_id,
        seq_num: SequenceNumber(tx_seq_num),
        op_num: 0,
    });
    let preimage_xdr = preimage
        .to_xdr(Limits::none())
        .map_err(|e| TestnetHelperError::new(e.to_string()))?;
    let balance_hash: [u8; 32] = Sha256::digest(&preimage_xdr).into();
    Ok(format!(
        "00000000{}",
        balance_hash
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
}

/// Outcome of a source-account-authorized invocation submitted by
/// [`invoke_as_source_account`].
pub struct SourceAccountInvocation<R> {
    /// The invocation's return value as the simulation reported it.
    pub return_value: ScVal,
    /// The caller's submission result for the confirmed transaction.
    pub submission: R,
    /// The simulation's Soroban transaction data (footprint and resources),
    /// attached unchanged to the submitted transaction.
    pub transaction_data: SorobanTransactionData,
}

/// Outcome of [`upload_and_create_contract`].
pub struct UploadedContract<R> {
    /// The created contract's C-strkey.
    pub contract: String,
    /// SHA-256 of the uploaded Wasm, the hash the contract's executable names.
    pub wasm_hash: [u8; 32],
    /// The upload transaction's submission result; `None` when a live code
    /// entry for `wasm_hash` already existed and no upload was submitted.
    pub upload: Option<R>,
    /// The create transaction's submission result.
    pub create: R,
}

/// Returns the C-strkey of the contract `deployer` creates with `salt` on the
/// network named by `network_passphrase`: the SHA-256 of the
/// `HashIdPreimage::ContractId` preimage over the network id and
/// `ContractIdPreimage::Address { deployer, salt }`.
///
/// # Errors
///
/// Returns an error when the preimage cannot be XDR-encoded.
pub fn derive_contract_address(
    deployer: &ScAddress,
    salt: &[u8; 32],
    network_passphrase: &str,
) -> TestnetHelperResult<String> {
    let network_id: [u8; 32] = Sha256::digest(network_passphrase.as_bytes()).into();
    let preimage = HashIdPreimage::ContractId(HashIdPreimageContractId {
        network_id: Hash(network_id),
        contract_id_preimage: ContractIdPreimage::Address(ContractIdPreimageFromAddress {
            address: deployer.clone(),
            salt: Uint256(*salt),
        }),
    });
    let preimage_xdr = preimage
        .to_xdr(Limits::none())
        .map_err(|e| TestnetHelperError::new(format!("contract-id preimage encode: {e}")))?;
    let contract_id: [u8; 32] = Sha256::digest(&preimage_xdr).into();
    Ok(format!("{}", stellar_strkey::Contract(contract_id)))
}

/// Parses a C-strkey into its `ScAddress::Contract`.
///
/// # Errors
///
/// Returns an error when `contract` is not a valid contract strkey.
pub fn contract_scaddress(contract: &str) -> TestnetHelperResult<ScAddress> {
    let parsed = stellar_strkey::Contract::from_string(contract)
        .map_err(|e| TestnetHelperError::new(format!("invalid contract strkey: {e}")))?;
    Ok(ScAddress::Contract(ContractId(Hash(parsed.0))))
}

/// Parses a G-strkey into its `ScAddress::Account`.
///
/// # Errors
///
/// Returns an error when `account` is not a valid ed25519 account strkey.
pub fn account_scaddress(account: &str) -> TestnetHelperResult<ScAddress> {
    let parsed = stellar_strkey::ed25519::PublicKey::from_string(account)
        .map_err(|e| TestnetHelperError::new(format!("invalid account strkey: {e}")))?;
    Ok(ScAddress::Account(AccountId(
        PublicKey::PublicKeyTypeEd25519(Uint256(parsed.0)),
    )))
}

/// Invokes `function_name` on `contract` with `args` in a transaction whose
/// source account `source_g` is the only authorizer, and waits for it to
/// confirm.
///
/// The transaction is simulated once; every authorization entry the
/// simulation requires must carry source-account credentials, which the
/// envelope signature satisfies, so a call needing any other authorizer is
/// refused before signing. The simulation's transaction data and resource fee
/// are attached unchanged. This drives contract functions that no wallet verb
/// reaches, such as test-infrastructure contracts.
///
/// Callers inject `fetch_sequence`, `sign_envelope` and `submit_signed_xdr`,
/// the dependency-injection style [`fund_sac_balance`] uses, so this module
/// takes no dependency on the wallet crates that use it in their tests.
///
/// # Errors
///
/// Returns an error when the contract strkey is invalid, the sequence fetch,
/// simulation, signing or submission fails, the simulation reports an error
/// or a required restoration, or it requires a non-source-account
/// authorization.
#[allow(
    clippy::too_many_arguments,
    reason = "acceptance helper keeps test-specific network hooks explicit at call sites"
)]
pub async fn invoke_as_source_account<F, FFut, S, SFut, Sub, SubFut, R>(
    rpc_url: &str,
    network_passphrase: &str,
    source_g: &str,
    source_seed: &Zeroizing<[u8; 32]>,
    contract: &str,
    function_name: &str,
    args: Vec<ScVal>,
    fetch_sequence: F,
    sign_envelope: S,
    submit_signed_xdr: Sub,
) -> TestnetHelperResult<SourceAccountInvocation<R>>
where
    F: Fn(&str) -> FFut,
    FFut: Future<Output = TestnetHelperResult<i64>>,
    S: FnOnce(String, Zeroizing<[u8; 32]>, &str) -> SFut,
    SFut: Future<Output = TestnetHelperResult<String>>,
    Sub: FnOnce(String) -> SubFut,
    SubFut: Future<Output = TestnetHelperResult<R>>,
{
    let function_name = ScSymbol::try_from(function_name)
        .map_err(|()| TestnetHelperError::new("function name is not a Soroban symbol"))?;
    let args: VecM<ScVal> = args
        .try_into()
        .map_err(|_| TestnetHelperError::new("invocation arguments exceed the XDR vector bound"))?;
    let host_function = HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: contract_scaddress(contract)?,
        function_name,
        args,
    });
    submit_source_authorized(
        rpc_url,
        network_passphrase,
        source_g,
        source_seed,
        host_function,
        &fetch_sequence,
        sign_envelope,
        submit_signed_xdr,
    )
    .await
}

/// Uploads `wasm` (skipped when a live code entry for its hash already
/// exists) and creates a contract from it with `CreateContractV2`, deployer
/// `deployer_g`, `salt` and `constructor_args`, in two source-account-signed
/// transactions.
///
/// The created address is checked against [`derive_contract_address`] and
/// the upload's returned hash against the Wasm's SHA-256.
///
/// # Errors
///
/// Returns an error when any RPC call, simulation, signing or submission
/// fails, or when the upload or create return value differs from the
/// locally derived hash or address.
#[allow(
    clippy::too_many_arguments,
    reason = "acceptance helper keeps test-specific network hooks explicit at call sites"
)]
pub async fn upload_and_create_contract<F, FFut, S, SFut, Sub, SubFut, R>(
    rpc_url: &str,
    network_passphrase: &str,
    deployer_g: &str,
    deployer_seed: &Zeroizing<[u8; 32]>,
    wasm: &[u8],
    salt: [u8; 32],
    constructor_args: Vec<ScVal>,
    fetch_sequence: F,
    sign_envelope: S,
    submit_signed_xdr: Sub,
) -> TestnetHelperResult<UploadedContract<R>>
where
    F: Fn(&str) -> FFut,
    FFut: Future<Output = TestnetHelperResult<i64>>,
    S: Fn(String, Zeroizing<[u8; 32]>, &str) -> SFut,
    SFut: Future<Output = TestnetHelperResult<String>>,
    Sub: Fn(String) -> SubFut,
    SubFut: Future<Output = TestnetHelperResult<R>>,
{
    let wasm_hash: [u8; 32] = Sha256::digest(wasm).into();
    let client = Client::new(rpc_url).map_err(|e| TestnetHelperError::new(e.to_string()))?;

    let code_key = LedgerKey::ContractCode(LedgerKeyContractCode {
        hash: Hash(wasm_hash),
    });
    let code_entries = retry_rpc!(client.get_ledger_entries(std::slice::from_ref(&code_key)))
        .map_err(|e| TestnetHelperError::new(e.to_string()))?;
    let latest_ledger = u32::try_from(code_entries.latest_ledger).map_err(|_| {
        TestnetHelperError::new(format!(
            "getLedgerEntries returned latest ledger {} outside the u32 range",
            code_entries.latest_ledger
        ))
    })?;
    let code_live = code_entries
        .entries
        .unwrap_or_default()
        .iter()
        .any(|entry| {
            entry
                .live_until_ledger_seq_ledger_seq
                .is_some_and(|live_until| live_until >= latest_ledger)
        });

    let upload = if code_live {
        None
    } else {
        let wasm_bytes: BytesM = wasm
            .to_vec()
            .try_into()
            .map_err(|_| TestnetHelperError::new("Wasm exceeds the XDR bytes bound"))?;
        let uploaded = submit_source_authorized(
            rpc_url,
            network_passphrase,
            deployer_g,
            deployer_seed,
            HostFunction::UploadContractWasm(wasm_bytes),
            &fetch_sequence,
            &sign_envelope,
            &submit_signed_xdr,
        )
        .await?;
        let expected_return =
            ScVal::Bytes(ScBytes(wasm_hash.to_vec().try_into().map_err(|_| {
                TestnetHelperError::new("hash exceeds the XDR bytes bound")
            })?));
        if uploaded.return_value != expected_return {
            return Err(Box::new(TestnetHelperError::new(
                "upload returned a hash other than the Wasm's SHA-256",
            )));
        }
        Some(uploaded.submission)
    };

    let deployer = account_scaddress(deployer_g)?;
    let expected_contract = derive_contract_address(&deployer, &salt, network_passphrase)?;
    let constructor_args: VecM<ScVal> = constructor_args
        .try_into()
        .map_err(|_| TestnetHelperError::new("constructor arguments exceed the XDR bound"))?;
    let created = submit_source_authorized(
        rpc_url,
        network_passphrase,
        deployer_g,
        deployer_seed,
        HostFunction::CreateContractV2(CreateContractArgsV2 {
            contract_id_preimage: ContractIdPreimage::Address(ContractIdPreimageFromAddress {
                address: deployer,
                salt: Uint256(salt),
            }),
            executable: ContractExecutable::Wasm(Hash(wasm_hash)),
            constructor_args,
        }),
        &fetch_sequence,
        &sign_envelope,
        &submit_signed_xdr,
    )
    .await?;
    if created.return_value != ScVal::Address(contract_scaddress(&expected_contract)?) {
        return Err(Box::new(TestnetHelperError::new(
            "create returned an address other than the derived contract address",
        )));
    }

    Ok(UploadedContract {
        contract: expected_contract,
        wasm_hash,
        upload,
        create: created.submission,
    })
}

/// Simulates `host_function` from `source_g`, attaches the simulation's
/// source-account authorization entries, transaction data and resource fee,
/// signs, and submits once.
#[allow(
    clippy::too_many_arguments,
    reason = "shared body of the source-account helpers; the hooks stay explicit"
)]
async fn submit_source_authorized<F, FFut, S, SFut, Sub, SubFut, R>(
    rpc_url: &str,
    network_passphrase: &str,
    source_g: &str,
    source_seed: &Zeroizing<[u8; 32]>,
    host_function: HostFunction,
    fetch_sequence: &F,
    sign_envelope: S,
    submit_signed_xdr: Sub,
) -> TestnetHelperResult<SourceAccountInvocation<R>>
where
    F: Fn(&str) -> FFut,
    FFut: Future<Output = TestnetHelperResult<i64>>,
    S: FnOnce(String, Zeroizing<[u8; 32]>, &str) -> SFut,
    SFut: Future<Output = TestnetHelperResult<String>>,
    Sub: FnOnce(String) -> SubFut,
    SubFut: Future<Output = TestnetHelperResult<R>>,
{
    let client = Client::new(rpc_url).map_err(|e| TestnetHelperError::new(e.to_string()))?;
    let sequence = retry_rpc!(fetch_sequence(source_g))?;

    let simulate_op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: host_function.clone(),
            auth: VecM::default(),
        }),
    };
    let mut simulate_account = BaselibAccount::new(source_g, &sequence.to_string())
        .map_err(|e| TestnetHelperError::new(e.to_string()))?;
    let mut simulate_builder =
        TransactionBuilder::new(&mut simulate_account, network_passphrase, None);
    simulate_builder.fee(BASE_FEE);
    simulate_builder.add_operation(simulate_op);
    let simulate_envelope = simulate_builder
        .build_for_simulation()
        .to_envelope()
        .map_err(|e| TestnetHelperError::new(e.to_string()))?;
    let simulation = retry_rpc!(client.simulate_transaction_envelope(&simulate_envelope, None))
        .map_err(|e| TestnetHelperError::new(e.to_string()))?;

    if let Some(err) = simulation.error {
        return Err(Box::new(TestnetHelperError::new(format!(
            "simulation returned an error: {err}"
        ))));
    }
    if simulation.restore_preamble.is_some() {
        return Err(Box::new(TestnetHelperError::new(
            "simulation requires restoring archived entries first",
        )));
    }
    let resource_fee = u32::try_from(simulation.min_resource_fee).map_err(|_| {
        TestnetHelperError::new(format!(
            "min_resource_fee {} overflows u32",
            simulation.min_resource_fee
        ))
    })?;
    let transaction_data = simulation
        .transaction_data()
        .map_err(|e| TestnetHelperError::new(e.to_string()))?;
    let result = simulation
        .results()
        .map_err(|e| TestnetHelperError::new(e.to_string()))?
        .into_iter()
        .next()
        .ok_or_else(|| TestnetHelperError::new("simulation returned no result"))?;
    if result
        .auth
        .iter()
        .any(|entry| !matches!(entry.credentials, SorobanCredentials::SourceAccount))
    {
        return Err(Box::new(TestnetHelperError::new(
            "simulation requires an authorization other than the source account's",
        )));
    }
    let auth: VecM<SorobanAuthorizationEntry> = result
        .auth
        .try_into()
        .map_err(|_| TestnetHelperError::new("authorization entries exceed the XDR bound"))?;

    let final_op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function,
            auth,
        }),
    };
    let mut final_account = BaselibAccount::new(source_g, &sequence.to_string())
        .map_err(|e| TestnetHelperError::new(e.to_string()))?;
    let mut final_builder = TransactionBuilder::new(&mut final_account, network_passphrase, None);
    final_builder.fee(BASE_FEE.saturating_add(resource_fee));
    final_builder.add_operation(final_op);
    let mut final_tx = final_builder.build_for_simulation();
    final_tx.soroban_data = Some(transaction_data.clone());
    let unsigned_xdr = final_tx
        .to_envelope()
        .map_err(|e| TestnetHelperError::new(e.to_string()))?
        .to_xdr_base64(Limits::none())
        .map_err(|e| TestnetHelperError::new(format!("envelope XDR encode: {e}")))?;

    let signed_xdr = sign_envelope(
        unsigned_xdr,
        Zeroizing::new(**source_seed),
        network_passphrase,
    )
    .await?;
    let submission = submit_signed_xdr(signed_xdr).await?;

    Ok(SourceAccountInvocation {
        return_value: result.xdr,
        submission,
        transaction_data,
    })
}

/// Bound on existence-check polls per confirm-wait round in
/// [`fund_with_friendbot`].
const FRIENDBOT_CONFIRM_POLLS: u32 = 30;

/// Delay between existence-check polls in [`fund_with_friendbot`]'s
/// confirm-wait (30 polls × 500ms ≈ 15s per round).
const FRIENDBOT_CONFIRM_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// The bounds of one Friendbot funding request: how many attempts start, how
/// long each may take, the pauses before the second and the third, and the
/// total time every attempt and pause share.
struct FriendbotRetryPolicy {
    /// Attempts that may start, the first included.
    attempts: u32,
    /// The longest one attempt may take, from connection through the body.
    attempt_timeout: Duration,
    /// The pause before the second attempt and before every later one.
    backoffs: [Duration; 2],
    /// The total time of one invocation, attempts and pauses included.
    deadline: Duration,
}

impl FriendbotRetryPolicy {
    /// The pause before the attempt that follows `started` attempts.
    fn backoff_after(&self, started: u32) -> Duration {
        let [first, later] = self.backoffs;
        if started <= 1 { first } else { later }
    }
}

/// The bounds of every live Friendbot funding request.
const FRIENDBOT_RETRY: FriendbotRetryPolicy = FriendbotRetryPolicy {
    attempts: 3,
    attempt_timeout: Duration::from_secs(20),
    backoffs: [Duration::from_millis(250), Duration::from_millis(500)],
    deadline: Duration::from_secs(65),
};

/// The bytes of a failure body [`friendbot_fund`] retains and inspects.
const FRIENDBOT_FAILURE_BODY_LIMIT: usize = 512;

/// Issues a Friendbot funding GET and returns the last response or error.
///
/// The funding request retries send failures and server errors within three
/// attempts and one total deadline. Each attempt opens a new connection and
/// takes at most 20 seconds, or the time left of the 65 second deadline when
/// that is shorter, from connection through the response body. The pauses
/// before the second and the third attempt are 250 and 500 milliseconds, and
/// they count against the same deadline. No attempt starts once the deadline
/// has passed.
///
/// A response that receives no further retry returns with its body unread.
/// That covers every status below 500, and a 5xx response the attempt count
/// or the deadline leaves without a further attempt. The response keeps the
/// attempt's timeout while the caller reads its body. A caller that cannot
/// read the body gets no new request.
///
/// URL parsing and client construction failures return before any request
/// starts.
///
/// # Errors
///
/// Returns the HTTP client's error when the URL does not parse or the client
/// cannot be built, and the last attempt's error when every attempt failed to
/// send, a timeout included.
pub async fn friendbot_funding_request(
    url: impl reqwest::IntoUrl,
) -> Result<reqwest::Response, reqwest::Error> {
    friendbot_request_with_policy(url, &FRIENDBOT_RETRY).await.0
}

/// Funds an account through the Friendbot request at `url`, a URL that
/// carries the account as its `addr` query parameter.
///
/// Funding succeeds on a successful HTTP status or a 400 response whose
/// bounded body reports that the account is already funded. The request
/// follows the retry policy of [`friendbot_funding_request`].
///
/// Failure diagnostics include the attempt count, the final status or
/// transport cause, and at most 512 bytes of the final body. The helper reads
/// failure bodies within the response timeout, and keeps the bytes it read
/// when the body ends in an error.
///
/// # Errors
///
/// [`FriendbotFundingError`] when the URL or the client cannot be built,
/// every attempt failed to send, or the final response is neither successful
/// nor an already funded 400.
pub async fn friendbot_fund(url: &str) -> Result<(), FriendbotFundingError> {
    friendbot_fund_with_policy(url, &FRIENDBOT_RETRY).await
}

/// [`friendbot_fund`] under `policy`.
async fn friendbot_fund_with_policy(
    url: &str,
    policy: &FriendbotRetryPolicy,
) -> Result<(), FriendbotFundingError> {
    let (outcome, attempts) = friendbot_request_with_policy(url, policy).await;
    let mut response = match outcome {
        Ok(response) => response,
        Err(error) => {
            return Err(FriendbotFundingError {
                attempts,
                cause: FundingCause::Transport(error),
                body: FailureBody::Unavailable,
            });
        }
    };
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let prefix = read_failure_body_prefix(&mut response).await;
    if status == reqwest::StatusCode::BAD_REQUEST && reports_already_funded(&prefix) {
        return Ok(());
    }
    Err(FriendbotFundingError {
        attempts,
        cause: FundingCause::Status(status),
        body: FailureBody::Prefix(prefix),
    })
}

/// Reads at most [`FRIENDBOT_FAILURE_BODY_LIMIT`] bytes of `response`'s body,
/// chunk by chunk, and keeps what arrived when the body ends in an error.
async fn read_failure_body_prefix(response: &mut reqwest::Response) -> Vec<u8> {
    let mut prefix = Vec::new();
    while prefix.len() < FRIENDBOT_FAILURE_BODY_LIMIT {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let room = FRIENDBOT_FAILURE_BODY_LIMIT - prefix.len();
                prefix.extend_from_slice(&chunk[..chunk.len().min(room)]);
            }
            Ok(None) | Err(_) => break,
        }
    }
    prefix
}

/// Whether a Friendbot failure body reports that the account is already
/// funded, compared without regard to ASCII case.
fn reports_already_funded(body: &[u8]) -> bool {
    String::from_utf8_lossy(body)
        .to_ascii_lowercase()
        .contains("already funded")
}

/// Runs the Friendbot request at `url` under `policy` and returns the last
/// outcome with the number of attempts that started.
///
/// The client is built once, without idle connections, so every attempt
/// connects anew. A send error and a 5xx status permit another attempt while
/// the attempt count and the deadline allow one; every other response ends
/// the run unread. An earlier response is dropped unread once the next
/// attempt starts.
async fn friendbot_request_with_policy(
    url: impl reqwest::IntoUrl,
    policy: &FriendbotRetryPolicy,
) -> (Result<reqwest::Response, reqwest::Error>, u32) {
    let deadline = tokio::time::Instant::now() + policy.deadline;
    let client = match reqwest::Client::builder().pool_max_idle_per_host(0).build() {
        Ok(client) => client,
        Err(error) => return (Err(error), 0),
    };
    let url = match client.get(url).build() {
        Ok(request) => request.url().clone(),
        Err(error) => return (Err(error), 0),
    };
    let mut attempts = 0;
    loop {
        let budget = deadline.saturating_duration_since(tokio::time::Instant::now());
        attempts += 1;
        let outcome = client
            .get(url.clone())
            .timeout(policy.attempt_timeout.min(budget))
            .send()
            .await;
        let retryable = match &outcome {
            Ok(response) => response.status().is_server_error(),
            Err(_) => true,
        };
        if !retryable || attempts >= policy.attempts {
            return (outcome, attempts);
        }
        // The pause counts against the deadline, and the deadline is checked
        // again before the next attempt starts.
        let resume = tokio::time::Instant::now() + policy.backoff_after(attempts);
        if resume >= deadline {
            return (outcome, attempts);
        }
        tokio::time::sleep_until(resume).await;
        if tokio::time::Instant::now() >= deadline {
            return (outcome, attempts);
        }
    }
}

/// Why [`friendbot_fund`] did not fund the account.
///
/// It carries the number of attempts that started, the final status or
/// transport cause, and at most 512 bytes of the final response body. Its
/// `Display` and `Debug` forms show all three.
pub struct FriendbotFundingError {
    attempts: u32,
    cause: FundingCause,
    body: FailureBody,
}

/// The final outcome of a failed funding request.
enum FundingCause {
    /// The final response's status, neither successful nor an already funded
    /// 400.
    Status(reqwest::StatusCode),
    /// The final error of the request, or of the URL or client construction.
    Transport(reqwest::Error),
}

/// The retained part of the final response body.
enum FailureBody {
    /// No response arrived, so no body exists.
    Unavailable,
    /// At most [`FRIENDBOT_FAILURE_BODY_LIMIT`] bytes of the body.
    Prefix(Vec<u8>),
}

/// The error and every source beneath it, joined by `": "`.
fn error_chain(error: &reqwest::Error) -> String {
    let mut text = error.to_string();
    let mut source = Error::source(error);
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

impl fmt::Display for FundingCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status(status) => write!(f, "HTTP status {status}"),
            Self::Transport(error) => f.write_str(&error_chain(error)),
        }
    }
}

impl fmt::Debug for FundingCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status(status) => write!(f, "Status({status})"),
            Self::Transport(error) => write!(f, "Transport({:?})", error_chain(error)),
        }
    }
}

impl fmt::Display for FailureBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("no response body is available"),
            Self::Prefix(bytes) => write!(f, "body {:?}", String::from_utf8_lossy(bytes)),
        }
    }
}

impl fmt::Debug for FailureBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("Unavailable"),
            Self::Prefix(bytes) => write!(f, "Prefix({:?})", String::from_utf8_lossy(bytes)),
        }
    }
}

impl fmt::Display for FriendbotFundingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let noun = if self.attempts == 1 {
            "attempt"
        } else {
            "attempts"
        };
        write!(
            f,
            "Friendbot did not fund the account after {} {noun}: {}; {}",
            self.attempts, self.cause, self.body
        )
    }
}

impl fmt::Debug for FriendbotFundingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FriendbotFundingError")
            .field("attempts", &self.attempts)
            .field("cause", &self.cause)
            .field("body", &self.body)
            .finish()
    }
}

impl Error for FriendbotFundingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.cause {
            FundingCause::Status(_) => None,
            FundingCause::Transport(error) => Some(error),
        }
    }
}

/// Requests Friendbot funding for `account_id`, then confirms the account
/// became visible on `rpc_url` before returning.
///
/// The funding REQUESTS are best-effort; on-RPC visibility is the sole pass
/// criterion. This shape covers three distinct environmental flakes without
/// weakening the check: Friendbot accepting a request whose transaction fails
/// to land under load (the `TxNoAccount` class), the HTTP request itself
/// timing out even though Friendbot may still process it, and a re-request
/// against an account that landed late (Friendbot rejects double funding, but
/// the account IS there). After one bounded confirm-wait the funding is
/// re-requested ONCE and a second bounded wait runs before giving up. A flow
/// whose account never becomes visible fails exactly as it did before — this
/// never converts a persistent Friendbot outage into a pass.
async fn fund_with_friendbot(
    friendbot_url: &str,
    rpc_url: &str,
    account_id: &str,
    label: &str,
) -> TestnetHelperResult<()> {
    let client = stellar_rpc_client::Client::new(rpc_url)
        .map_err(|e| TestnetHelperError::new(e.to_string()))?;

    if let Err(e) = request_friendbot_funding(friendbot_url, account_id, label).await {
        eprintln!(
            "{label}: Friendbot request failed ({e}); polling visibility before one re-request"
        );
    }
    if wait_for_account_visible(&client, account_id).await {
        return Ok(());
    }

    eprintln!(
        "{label}: account not visible after the confirm wait; re-requesting Friendbot funding once"
    );
    if let Err(e) = request_friendbot_funding(friendbot_url, account_id, label).await {
        eprintln!("{label}: Friendbot re-request failed ({e}); final visibility poll decides");
    }
    if wait_for_account_visible(&client, account_id).await {
        return Ok(());
    }

    Err(Box::new(TestnetHelperError::new(format!(
        "Friendbot-funded {label} still not visible on RPC after a re-request"
    ))))
}

/// Issues the Friendbot HTTP funding request. Does not confirm the account
/// became visible — see [`fund_with_friendbot`] for the confirm-wait.
async fn request_friendbot_funding(
    friendbot_url: &str,
    account_id: &str,
    label: &str,
) -> TestnetHelperResult<()> {
    let response = friendbot_funding_request(format!("{friendbot_url}?addr={account_id}")).await?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(Box::new(TestnetHelperError::new(format!(
            "Friendbot must fund {label}; got {}",
            response.status()
        ))))
    }
}

/// Polls `account_id`'s presence on `client`, bounded by
/// [`FRIENDBOT_CONFIRM_POLLS`] / [`FRIENDBOT_CONFIRM_POLL_INTERVAL`].
async fn wait_for_account_visible(client: &stellar_rpc_client::Client, account_id: &str) -> bool {
    for attempt in 0..FRIENDBOT_CONFIRM_POLLS {
        if attempt > 0 {
            tokio::time::sleep(FRIENDBOT_CONFIRM_POLL_INTERVAL).await;
        }
        if client.get_account(account_id).await.is_ok() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        reason = "test fixtures and assertions"
    )]

    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::{JoinHandle, JoinSet};
    use tokio::time::Instant;

    const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    const BUSY: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
    const ALREADY_FUNDED: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 63\r\n\r\n\
        {\"detail\": \"createAccountAlreadyExist: Account Already Funded\"}";

    /// What the fixture does with one request, chosen by the request's
    /// position among all requests the fixture received.
    #[derive(Clone)]
    enum Answer {
        /// Writes these bytes and keeps the connection open; no bytes leave
        /// the request unanswered.
        Bytes(Vec<u8>),
        /// Closes the connection without an answer.
        Close,
        /// Resets the connection without an answer.
        Reset,
    }

    fn bytes(response: &[u8]) -> Answer {
        Answer::Bytes(response.to_vec())
    }

    fn stall() -> Answer {
        Answer::Bytes(Vec::new())
    }

    /// Accepted connections and the connection of every request, in arrival
    /// order.
    #[derive(Default)]
    struct Record {
        connections: Vec<Instant>,
        requests: Vec<usize>,
    }

    /// A loopback Friendbot that answers each request from a script and keeps
    /// every accepted connection open until the client closes it.
    struct Friendbot {
        url: String,
        record: Arc<Mutex<Record>>,
        server: JoinHandle<()>,
    }

    impl Friendbot {
        fn connections(&self) -> Vec<Instant> {
            self.record.lock().expect("record").connections.clone()
        }

        fn requests(&self) -> Vec<usize> {
            self.record.lock().expect("record").requests.clone()
        }
    }

    impl Drop for Friendbot {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    fn friendbot_url(address: SocketAddr) -> String {
        format!("http://{address}/?addr=test-account")
    }

    /// Serves `answers` on a new loopback listener. A request beyond the
    /// script receives the last answer.
    async fn friendbot_serving(answers: Vec<Answer>) -> Friendbot {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        serve(listener, answers)
    }

    fn serve(listener: TcpListener, answers: Vec<Answer>) -> Friendbot {
        let url = friendbot_url(listener.local_addr().expect("address"));
        let record = Arc::new(Mutex::new(Record::default()));
        let answers = Arc::new(answers);
        let shared = Arc::clone(&record);
        let server = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                let (socket, _) = listener.accept().await.expect("accept request");
                let connection = {
                    let mut record = shared.lock().expect("record");
                    record.connections.push(Instant::now());
                    record.connections.len() - 1
                };
                connections.spawn(answer_connection(
                    socket,
                    connection,
                    Arc::clone(&shared),
                    Arc::clone(&answers),
                ));
            }
        });
        Friendbot {
            url,
            record,
            server,
        }
    }

    /// Answers every request on `socket` until the client closes it or an
    /// answer ends the connection.
    async fn answer_connection(
        mut socket: TcpStream,
        connection: usize,
        record: Arc<Mutex<Record>>,
        answers: Arc<Vec<Answer>>,
    ) {
        let mut pending = Vec::new();
        loop {
            let end = loop {
                if let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                    break end + 4;
                }
                let mut chunk = [0; 1024];
                let count = socket.read(&mut chunk).await.unwrap_or(0);
                if count == 0 {
                    return;
                }
                pending.extend_from_slice(&chunk[..count]);
            };
            let request: Vec<u8> = pending.drain(..end).collect();
            assert!(request.starts_with(b"GET /?addr=test-account "));
            let ordinal = {
                let mut record = record.lock().expect("record");
                record.requests.push(connection);
                record.requests.len() - 1
            };
            let answer = answers
                .get(ordinal)
                .or(answers.last())
                .cloned()
                .expect("a scripted answer");
            match answer {
                Answer::Bytes(response) => {
                    socket.write_all(&response).await.expect("write response");
                }
                Answer::Close => return,
                Answer::Reset => {
                    socket.set_zero_linger().expect("zero linger");
                    return;
                }
            }
        }
    }

    /// The fixture every earlier test used: each request receives `response`.
    async fn friendbot_response(response: &'static [u8]) -> (String, Friendbot) {
        let friendbot = friendbot_serving(vec![bytes(response)]).await;
        (friendbot.url.clone(), friendbot)
    }

    fn policy(
        attempts: u32,
        attempt_timeout_ms: u64,
        backoffs_ms: [u64; 2],
        deadline_ms: u64,
    ) -> FriendbotRetryPolicy {
        FriendbotRetryPolicy {
            attempts,
            attempt_timeout: Duration::from_millis(attempt_timeout_ms),
            backoffs: backoffs_ms.map(Duration::from_millis),
            deadline: Duration::from_millis(deadline_ms),
        }
    }

    /// A policy whose pauses keep the tests short.
    fn quick() -> FriendbotRetryPolicy {
        policy(3, 2_000, [50, 50], 10_000)
    }

    fn status_of(outcome: Result<reqwest::Response, reqwest::Error>) -> reqwest::StatusCode {
        outcome.expect("HTTP response").status()
    }

    #[tokio::test]
    async fn friendbot_request_preserves_http_failure_status_and_body() {
        let (url, server) = friendbot_response(
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\nbusy",
        )
        .await;
        let response = friendbot_funding_request(&url)
            .await
            .expect("HTTP response");
        assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.text().await.expect("response body"), "busy");
        drop(server);
    }

    #[tokio::test]
    async fn friendbot_deadline_bounds_stalled_headers_and_body() {
        for headers in [
            b"".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n".as_slice(),
        ] {
            let (url, server) = friendbot_response(headers).await;
            let error = tokio::time::timeout(Duration::from_secs(5), async {
                let response = friendbot_request_with_policy(&url, &policy(1, 200, [0, 0], 200))
                    .await
                    .0;
                if headers.is_empty() {
                    response.expect_err("stalled headers must time out")
                } else {
                    response
                        .expect("headers must arrive before the deadline")
                        .text()
                        .await
                        .expect_err("stalled body must time out")
                }
            })
            .await
            .expect("request deadline must bound stalled I/O");
            drop(server);
            assert!(error.is_timeout(), "expected request timeout: {error}");
        }
    }

    /// A timed out attempt is followed, after the first pause, by a second
    /// one on a new connection.
    #[tokio::test]
    async fn friendbot_timeout_retries_then_succeeds() {
        let friendbot = friendbot_serving(vec![stall(), bytes(OK)]).await;

        let (outcome, attempts) =
            friendbot_request_with_policy(&friendbot.url, &policy(3, 150, [200, 900], 10_000))
                .await;

        assert_eq!(status_of(outcome), reqwest::StatusCode::OK);
        assert_eq!(attempts, 2);
        assert_eq!(friendbot.requests(), [0, 1]);
        let connections = friendbot.connections();
        let gap = connections[1] - connections[0];
        assert!(
            gap >= Duration::from_millis(350) && gap < Duration::from_millis(1_050),
            "the second attempt follows the timeout and the first pause: {gap:?}"
        );
    }

    /// A refused connection is followed by a second attempt.
    #[tokio::test]
    async fn friendbot_connection_error_retries_then_succeeds() {
        let probe = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let address = probe.local_addr().expect("address");
        drop(probe);
        let url = friendbot_url(address);
        let retry = policy(3, 2_000, [400, 400], 10_000);

        let ((outcome, attempts), friendbot) =
            tokio::join!(friendbot_request_with_policy(&url, &retry), async {
                // The first attempt meets no listener; the second meets this
                // one.
                tokio::time::sleep(Duration::from_millis(100)).await;
                let listener = TcpListener::bind(address).await.expect("bind again");
                serve(listener, vec![bytes(OK)])
            },);

        assert_eq!(status_of(outcome), reqwest::StatusCode::OK);
        assert_eq!(attempts, 2, "the refused attempt counts");
        assert_eq!(friendbot.requests(), [0], "the listener sees the second");
    }

    /// A connection reset after the request was sent is retried.
    #[tokio::test]
    async fn friendbot_reset_after_send_retries_then_succeeds() {
        let friendbot = friendbot_serving(vec![Answer::Reset, bytes(OK)]).await;

        let (outcome, attempts) = friendbot_request_with_policy(&friendbot.url, &quick()).await;

        assert_eq!(status_of(outcome), reqwest::StatusCode::OK);
        assert_eq!(attempts, 2);
        assert_eq!(friendbot.requests(), [0, 1]);
    }

    #[tokio::test]
    async fn friendbot_server_error_retries_then_succeeds() {
        let friendbot = friendbot_serving(vec![bytes(BUSY), bytes(OK)]).await;

        let (outcome, attempts) = friendbot_request_with_policy(&friendbot.url, &quick()).await;

        assert_eq!(status_of(outcome), reqwest::StatusCode::OK);
        assert_eq!(attempts, 2);
        assert_eq!(friendbot.requests(), [0, 1]);
    }

    /// A status below 500 ends the run on its first answer, its body still
    /// unread for the caller.
    #[tokio::test]
    async fn friendbot_other_client_errors_stop() {
        for (status, response) in [
            (
                400,
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 5\r\n\r\nfirst".as_slice(),
            ),
            (
                401,
                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 5\r\n\r\nfirst".as_slice(),
            ),
            (
                403,
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 5\r\n\r\nfirst".as_slice(),
            ),
            (
                404,
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\n\r\nfirst".as_slice(),
            ),
        ] {
            let friendbot = friendbot_serving(vec![bytes(response), bytes(OK)]).await;

            let (outcome, attempts) = friendbot_request_with_policy(&friendbot.url, &quick()).await;

            let response = outcome.expect("HTTP response");
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(attempts, 1, "{status}");
            assert_eq!(friendbot.requests(), [0], "{status}: the queued 200 stays");
            assert_eq!(response.text().await.expect("body"), "first", "{status}");
        }
    }

    #[tokio::test]
    async fn friendbot_unbuildable_url_sends_nothing() {
        for url in ["not a url", "http://", "mailto:account@example.invalid"] {
            let (outcome, attempts) = friendbot_request_with_policy(url, &quick()).await;
            let error = outcome.expect_err("the URL cannot be built");
            assert!(error.is_builder(), "{url}: {error}");
            assert_eq!(attempts, 0, "{url}");

            let error = friendbot_fund_with_policy(url, &quick())
                .await
                .expect_err("the URL cannot be built");
            assert_eq!(error.attempts, 0, "{url}");
            assert!(matches!(error.body, FailureBody::Unavailable), "{url}");
            assert!(error.to_string().contains("after 0 attempts"), "{error}");
        }
    }

    /// The third failure ends the run, and the error reports it, not the
    /// first.
    #[tokio::test]
    async fn friendbot_attempt_limit_keeps_last_failure() {
        let friendbot = friendbot_serving(vec![Answer::Close, stall(), stall(), bytes(OK)]).await;

        let error = friendbot_fund_with_policy(&friendbot.url, &policy(3, 150, [50, 50], 10_000))
            .await
            .expect_err("three failed attempts");

        assert_eq!(friendbot.requests(), [0, 1, 2], "no fourth request");
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(display.contains("after 3 attempts"), "{display}");
        assert!(debug.contains("attempts: 3"), "{debug}");
        for text in [&display, &debug] {
            assert!(text.contains("timed out"), "the final cause: {text}");
            assert!(
                !text.contains("connection closed"),
                "the first cause: {text}"
            );
            assert!(
                !text.contains("IncompleteMessage"),
                "the first cause: {text}"
            );
        }
        assert!(
            display.contains("no response body is available"),
            "{display}"
        );
        assert!(debug.contains("body: Unavailable"), "{debug}");
    }

    /// A pause that would end past the deadline starts no further attempt and
    /// keeps the failure before it.
    #[tokio::test]
    async fn friendbot_total_deadline_includes_backoff() {
        let friendbot = friendbot_serving(vec![stall(), bytes(OK)]).await;

        let (outcome, attempts) =
            friendbot_request_with_policy(&friendbot.url, &policy(3, 100, [400, 400], 300)).await;

        let error = outcome.expect_err("the stalled attempt is the outcome");
        assert!(error.is_timeout(), "{error}");
        assert_eq!(attempts, 1, "no attempt starts after the deadline");
        assert_eq!(friendbot.requests(), [0]);
    }

    /// The last attempt receives only the time the deadline leaves.
    #[tokio::test]
    async fn friendbot_remaining_budget_bounds_request() {
        let friendbot = friendbot_serving(vec![bytes(BUSY), bytes(BUSY), stall()]).await;
        let started = Instant::now();

        let (outcome, attempts) = tokio::time::timeout(
            Duration::from_secs(10),
            friendbot_request_with_policy(&friendbot.url, &policy(3, 3_000, [50, 50], 600)),
        )
        .await
        .expect("the run ends");

        let elapsed = started.elapsed();
        let error = outcome.expect_err("the stalled attempt is the outcome");
        assert!(error.is_timeout(), "{error}");
        assert_eq!(attempts, 3);
        assert_eq!(friendbot.requests(), [0, 1, 2]);
        assert!(
            elapsed < Duration::from_millis(1_500),
            "the original deadline ends the stalled attempt: {elapsed:?}"
        );
    }

    /// Every attempt opens its own connection: a reusable connection after a
    /// complete 503 answer carries no second request.
    #[tokio::test]
    async fn friendbot_retries_use_fresh_connections() {
        let friendbot = friendbot_serving(vec![bytes(BUSY), bytes(OK)]).await;

        let (outcome, attempts) = friendbot_request_with_policy(&friendbot.url, &quick()).await;

        assert_eq!(status_of(outcome), reqwest::StatusCode::OK);
        assert_eq!(attempts, 2);
        assert_eq!(friendbot.connections().len(), 2, "two accepted connections");
        assert_eq!(friendbot.requests(), [0, 1], "one request on each");
    }

    #[tokio::test]
    async fn friendbot_fund_accepts_success_and_already_funded() {
        for response in [
            OK,
            b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n".as_slice(),
            ALREADY_FUNDED,
        ] {
            let friendbot = friendbot_serving(vec![bytes(response)]).await;
            friendbot_fund_with_policy(&friendbot.url, &quick())
                .await
                .expect("funded");
        }

        let friendbot = friendbot_serving(vec![bytes(
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 30\r\n\r\nthe address is not a valid key",
        )])
        .await;
        let error = friendbot_fund_with_policy(&friendbot.url, &quick())
            .await
            .expect_err("a 400 of another kind refuses");
        assert!(
            matches!(error.cause, FundingCause::Status(status) if status == reqwest::StatusCode::BAD_REQUEST),
            "{error:?}"
        );
        assert_eq!(error.attempts, 1);
        assert!(
            error.to_string().contains("the address is not a valid key"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn friendbot_timeout_then_already_funded_succeeds() {
        let friendbot = friendbot_serving(vec![stall(), bytes(ALREADY_FUNDED)]).await;

        friendbot_fund_with_policy(&friendbot.url, &policy(3, 150, [50, 50], 10_000))
            .await
            .expect("an account funded by the timed out attempt counts as funded");

        assert_eq!(friendbot.requests(), [0, 1], "two attempts");
    }

    /// Only the first 512 bytes of a failure body are kept and inspected.
    #[tokio::test]
    async fn friendbot_fund_bounds_failure_body() {
        fn bad_request(body: &[u8]) -> Answer {
            let mut response = format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes();
            response.extend_from_slice(body);
            Answer::Bytes(response)
        }
        let filler = vec![b'x'; FRIENDBOT_FAILURE_BODY_LIMIT];
        let tail = vec![b'y'; 64 * 1024];

        let beyond = [filler.as_slice(), b"already funded", &tail].concat();
        let friendbot = friendbot_serving(vec![bad_request(&beyond)]).await;
        let error = friendbot_fund_with_policy(&friendbot.url, &quick())
            .await
            .expect_err("text beyond the prefix does not classify");
        match &error.body {
            FailureBody::Prefix(prefix) => assert_eq!(prefix, &filler),
            FailureBody::Unavailable => panic!("a body arrived: {error:?}"),
        }

        let within = [b"already funded".as_slice(), &tail].concat();
        let friendbot = friendbot_serving(vec![bad_request(&within)]).await;
        friendbot_fund_with_policy(&friendbot.url, &quick())
            .await
            .expect("the prefix reports an already funded account");
    }

    /// The error reports the final answer: its status, its body, and the
    /// number of attempts.
    #[tokio::test]
    async fn friendbot_fund_reports_final_status_body_and_attempts() {
        let friendbot = friendbot_serving(vec![
            bytes(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nfirst"),
            bytes(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 6\r\n\r\nsecond"),
            bytes(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 5\r\n\r\nthird"),
        ])
        .await;

        let error = friendbot_fund_with_policy(&friendbot.url, &quick())
            .await
            .expect_err("three server errors");

        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(display.contains("after 3 attempts"), "{display}");
        assert!(debug.contains("attempts: 3"), "{debug}");
        for text in [&display, &debug] {
            assert!(text.contains("503"), "{text}");
            assert!(text.contains("third"), "{text}");
            assert!(!text.contains("first"), "{text}");
            assert!(!text.contains("500"), "{text}");
        }
    }
}
