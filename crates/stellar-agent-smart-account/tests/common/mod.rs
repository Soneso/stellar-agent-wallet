//! Shared helpers for testnet acceptance tests in this crate.
//!
//! Each test file that requires live testnet access uses `mod common;` to
//! pull in these constants, the `fund_via_friendbot` helper, the sequence /
//! sign / submit hooks the test-support live helpers take, and the
//! source-account deploy and invoke wrappers, so the endpoint set and the
//! transaction plumbing have a single definition per crate.
//!
//! Only compiled when the `testnet-integration` feature is active; callers
//! guard the top of their file with `#![cfg(feature = "testnet-integration")]`.

#![cfg(feature = "testnet-integration")]
#![allow(dead_code, reason = "helpers are selectively used across test files")]

use std::error::Error;
use std::time::Duration;

use stellar_agent_core::StellarAmount;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::submit::{
    SubmissionResult, SubmissionSignerKind, submit_transaction_and_wait,
};
use stellar_agent_network::{SoftwareSigningKey, StellarRpcClient, fetch_account};
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::rules::{
    parse_c_strkey_to_smart_account, parse_g_strkey_to_signer_address,
};
use stellar_agent_test_support::testnet_helpers::{
    SourceAccountInvocation, TestnetHelperResult, UploadedContract,
};
use stellar_xdr::{
    HostFunction, Int128Parts, InvokeContractArgs, ScAddress, ScSymbol, ScVal, VecM,
};
use zeroize::Zeroizing;

/// Soroban RPC endpoint for SDF testnet.
pub const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";

/// Friendbot endpoint for testnet account funding.
pub const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";

/// Network passphrase for SDF testnet.
pub const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Known-answer XLM SAC on testnet (SEP-41 native-asset contract).
///
/// Source: `soroswap-core/public/tokens.json:testnet:assets[0]:contract`;
/// independently verified via `stellar contract id asset --asset native
/// --network testnet`. Also a known-answer test in `stellar-agent-dex/src/sac.rs`.
pub const XLM_SAC_TESTNET: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

/// Submit-and-confirm budget of [`submit_testnet_signed_xdr`].
const SUBMIT_TIMEOUT: Duration = Duration::from_secs(120);

/// Ensures an account is funded via testnet Friendbot.
///
/// Friendbot refuses to fund an account that already exists, answering 400
/// with an "account already funded to starting balance" detail; for this
/// helper's postcondition (the account exists and holds XLM) that state is
/// success. Fixed well-known accounts such as the interop deployer hit it on
/// every run after their first funding. Panics if the HTTP request fails or
/// Friendbot answers with anything else.
pub async fn fund_via_friendbot(g_strkey: &str) {
    let url = format!("{TESTNET_FRIENDBOT_URL}?addr={g_strkey}");
    let resp = stellar_agent_test_support::testnet_helpers::friendbot_funding_request(&url)
        .await
        .expect("Friendbot HTTP request must succeed");
    let status = resp.status();
    if status.is_success() {
        return;
    }
    let body = resp.text().await.unwrap_or_default();
    assert!(
        status == reqwest::StatusCode::BAD_REQUEST && body.contains("account already funded"),
        "Friendbot must fund {g_strkey}; got {status}: {body}"
    );
}

/// Fetches an account's current sequence number via the testnet RPC.
pub async fn fetch_testnet_sequence(
    account_id: String,
) -> Result<i64, Box<dyn Error + Send + Sync>> {
    let rpc_client = StellarRpcClient::new(TESTNET_RPC_URL)?;
    let account = fetch_account(&rpc_client, &account_id, &[]).await?;
    Ok(account.sequence_number)
}

/// Signs an unsigned envelope XDR with a raw ed25519 seed.
pub async fn sign_testnet_envelope(
    unsigned_xdr: String,
    seed: Zeroizing<[u8; 32]>,
    network_passphrase: String,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    let signer = SoftwareSigningKey::new_from_zeroizing(seed);
    Ok(attach_signature(&unsigned_xdr, &signer, &network_passphrase).await?)
}

/// Submits a signed envelope XDR and waits for confirmation.
pub async fn submit_testnet_signed_xdr(
    signed_xdr: String,
) -> Result<SubmissionResult, Box<dyn Error + Send + Sync>> {
    let rpc_client = StellarRpcClient::new(TESTNET_RPC_URL)?;
    Ok(submit_transaction_and_wait(
        &rpc_client,
        &signed_xdr,
        SUBMIT_TIMEOUT,
        TESTNET_PASSPHRASE,
        Some(SubmissionSignerKind::Software),
        None,
    )
    .await?)
}

/// Returns the classic native (XLM) balance of `g_strkey`, in exact stroops.
///
/// Reads the ledger-derived `AccountView.balances` (not Horizon); native SAC
/// balance for a G-account is the classic XLM balance.
pub async fn xlm_stroops_balance(g_strkey: &str) -> i64 {
    let rpc_client = StellarRpcClient::new(TESTNET_RPC_URL).expect("testnet RPC URL must be valid");
    let account = fetch_account(&rpc_client, g_strkey, &[])
        .await
        .expect("fetch_account must succeed");
    let native = account
        .balances
        .iter()
        .find(|b| b.asset.asset_type == "native")
        .expect("account must have a native balance entry");
    StellarAmount::parse_with_unit(&format!("{} XLM", native.balance))
        .expect("native balance decimal string must parse as a StellarAmount")
        .as_stroops()
}

/// Uploads `wasm` and creates a contract from it on testnet, deployer
/// `deployer_g` (signing with `deployer_seed`), `salt` and
/// `constructor_args`; see
/// [`stellar_agent_test_support::testnet_helpers::upload_and_create_contract`].
pub async fn upload_and_create_contract(
    wasm: &[u8],
    deployer_g: &str,
    deployer_seed: &Zeroizing<[u8; 32]>,
    salt: [u8; 32],
    constructor_args: Vec<ScVal>,
) -> TestnetHelperResult<UploadedContract<SubmissionResult>> {
    stellar_agent_test_support::testnet_helpers::upload_and_create_contract(
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
        deployer_g,
        deployer_seed,
        wasm,
        salt,
        constructor_args,
        |account_id| fetch_testnet_sequence(account_id.to_owned()),
        |unsigned_xdr, seed, network_passphrase| {
            sign_testnet_envelope(unsigned_xdr, seed, network_passphrase.to_owned())
        },
        submit_testnet_signed_xdr,
    )
    .await
}

/// Invokes `function_name(args)` on `contract` on testnet in a transaction
/// whose source account `signer_g` (signing with `signer_seed`) is the only
/// authorizer; see
/// [`stellar_agent_test_support::testnet_helpers::invoke_as_source_account`].
pub async fn invoke_as_source_account(
    contract: &str,
    function_name: &str,
    args: Vec<ScVal>,
    signer_g: &str,
    signer_seed: &Zeroizing<[u8; 32]>,
) -> TestnetHelperResult<SourceAccountInvocation<SubmissionResult>> {
    stellar_agent_test_support::testnet_helpers::invoke_as_source_account(
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
        signer_g,
        signer_seed,
        contract,
        function_name,
        args,
        |account_id| fetch_testnet_sequence(account_id.to_owned()),
        |unsigned_xdr, seed, network_passphrase| {
            sign_testnet_envelope(unsigned_xdr, seed, network_passphrase.to_owned())
        },
        submit_testnet_signed_xdr,
    )
    .await
}

/// Builds the SEP-41 `transfer(from, to, amount)` `HostFunction::InvokeContract`
/// invocation for a SAC: the only shape the OZ spending-limit policy's
/// `enforce` accepts (`spending_limit.rs:222-292`, SHA `a9c4216`).
pub fn transfer_host_function(
    sac: ScAddress,
    from: ScAddress,
    to: ScAddress,
    amount: i128,
) -> HostFunction {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "canonical i128 -> Int128Parts split: hi = high 64 bits, lo = low 64 bits"
    )]
    let amount_parts = Int128Parts {
        hi: (amount >> 64) as i64,
        lo: amount as u64,
    };
    let args: VecM<ScVal> = vec![
        ScVal::Address(from),
        ScVal::Address(to),
        ScVal::I128(amount_parts),
    ]
    .try_into()
    .expect("3-element transfer args vec fits VecM<ScVal>");
    let function_name =
        ScSymbol::try_from("transfer").expect("\"transfer\" fits ScSymbol (<=32 bytes)");
    HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: sac,
        function_name,
        args,
    })
}

/// Builds the `InvokeContractArgs` for `fund_sac_balance`'s SAC-transfer
/// callback: plain structural strkey parsing, no network access.
#[allow(
    clippy::result_large_err,
    reason = "SaError is the crate's production error type; this test-only builder \
              surfaces it unchanged rather than introducing a narrower local error type"
)]
pub fn build_sac_transfer_invoke(
    sac_contract: &str,
    from: &str,
    to: &str,
    amount: i128,
) -> Result<InvokeContractArgs, SaError> {
    let contract_address = parse_c_strkey_to_smart_account(sac_contract)?;
    let from_sc = parse_g_strkey_to_signer_address(from)?;
    let to_sc = parse_c_strkey_to_smart_account(to)?;
    let HostFunction::InvokeContract(invoke_args) =
        transfer_host_function(contract_address, from_sc, to_sc, amount)
    else {
        unreachable!("transfer_host_function always returns InvokeContract");
    };
    Ok(invoke_args)
}
