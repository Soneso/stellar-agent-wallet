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
use stellar_baselib::{
    account::{Account as BaselibAccount, AccountBehavior},
    transaction::TransactionBehavior,
    transaction_builder::{TransactionBuilder, TransactionBuilderBehavior},
    xdr::{
        HostFunction, InvokeContractArgs, InvokeHostFunctionOp, Limits, Operation, OperationBody,
        SorobanAuthorizationEntry, SorobanCredentials, VecM, WriteXdr,
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

    fund_with_friendbot(friendbot_url, &signer_g_strkey, "signer G-account").await?;
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

    fund_with_friendbot(friendbot_url, &deployer_g_strkey, "deployer").await?;
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

    fund_with_friendbot(friendbot_url, &funder_g, "funder G-account").await?;
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

    // stellar-baselib 0.5.8 re-exports the workspace stellar_xdr directly, so
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
    // min_resource_fee is u64 in rpc-client 27 (deserialised from the JSON number-as-string
    // field, defaulting to 0 when absent).  A value of 0 means the simulate response did not
    // return resource fee information.
    if sim_resp.min_resource_fee == 0 {
        return Err(Box::new(TestnetHelperError::new(
            "SAC transfer first simulate did not return min_resource_fee",
        )));
    }

    // results()[0].auth contains the SorobanAuthorizationEntry values returned by the RPC.
    // stellar-baselib 0.5.8 uses the same stellar_xdr as the workspace, so these entries
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

async fn fund_with_friendbot(
    friendbot_url: &str,
    account_id: &str,
    label: &str,
) -> TestnetHelperResult<()> {
    let response = reqwest::get(format!("{friendbot_url}?addr={account_id}")).await?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(Box::new(TestnetHelperError::new(format!(
            "Friendbot must fund {label}; got {}",
            response.status()
        ))))
    }
}
