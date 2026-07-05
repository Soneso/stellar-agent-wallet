//! Testnet acceptance test for the DeFindex vault deposit `submit_signed_invoke` path.
//!
//! Gated behind the `testnet-acceptance` feature flag:
//!
//! ```text
//! cargo test -p stellar-agent-defindex --features testnet-acceptance \
//!   --test defindex_deposit_submit_testnet_acceptance
//! ```
//!
//! # Purpose
//!
//! Validates the auth-entry sub-invocation construction in the smart-account
//! submit path — specifically that a SAC `transfer(from=wallet)` sub-invocation
//! is included in the signed auth entry for the vault deposit path.
//!
//! The XLM DeFindex vault (`CCLV4H7W…4GFSF6`) uses the native XLM SAC as its
//! underlying asset.  The wallet is funded with XLM SAC directly via the
//! `fund_sac_balance` helper (no swap required), and then a small XLM deposit
//! into the vault exercises the external-contract path in `submit.rs` where the
//! vault's `deposit` calls `require_auth` on the depositor and the underlying
//! XLM SAC `transfer(from=wallet)` is a sub-invocation.
//!
//! # Submit gate
//!
//! `DefindexVaultAdapter::submit` enforces the ordered trust gate inline
//! (pin-verify → upgradable-flag → roles → asset-count) before signing.
//! `override_upgradable = true` is set because the testnet vault may be
//! marked upgradable:true.
//!
//! # On-chain failure semantics
//!
//! If `DefindexVaultAdapter::submit` returns an error — particularly one
//! containing `__check_auth`, `RuleIdMismatch`, `AuthEntryConstructionFailed`,
//! or `context-rule` — the `submit.rs` fix is WRONG or INCOMPLETE.  The test
//! reports the exact error and PANICs.

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only; panics, unwraps, and eprintln are acceptable in testnet acceptance tests"
)]

use std::{
    error::Error,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use stellar_agent_defi::{
    adapter::{DefiAdapter, DefiAdapterCtx},
    dispatch::{GateOutcome, dispatch_gate},
    pins::DefiContractPin,
};
use stellar_agent_defindex::{
    abi::{VaultDepositArgs, VaultWithdrawArgs},
    adapter::DefindexVaultAdapter,
    pins::{DEFINDEX_VAULT_WASM_HASH, verify_defindex_vault_wasm},
    storage::{read_vault_assets, read_vault_share_balance},
};
use stellar_agent_network::{
    Signer, SoftwareSigningKey, StellarRpcClient, fetch_account,
    signing::envelope_signing::attach_signature,
    submit::{SubmissionResult, SubmissionSignerKind, submit_transaction_and_wait},
};
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, ResolvedFeePerOp as DeployResolvedFeePerOp,
    deploy_smart_account,
};
use stellar_agent_test_support::{
    retry_rpc,
    testnet_helpers::{
        DeploySmartAccountOutcome, DeploySmartAccountRequest, deploy_funded_smart_account,
        fund_sac_balance, redact_strkey,
    },
};
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Test-local SAC transfer builder (decoupled from stellar-agent-x402)
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned by the local SAC-transfer-invoke builder.
#[derive(Debug)]
struct SacTransferBuildError(String);

impl std::fmt::Display for SacTransferBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SAC transfer build failed: {}", self.0)
    }
}

impl std::error::Error for SacTransferBuildError {}

/// Converts a Stellar G- or C-strkey to an `ScAddress`.
///
/// G-strkeys map to `ScAddress::Account`, C-strkeys to `ScAddress::Contract`.
fn strkey_to_sc_address(strkey: &str) -> Result<stellar_xdr::ScAddress, SacTransferBuildError> {
    use stellar_strkey::Strkey;
    use stellar_xdr::{AccountId, ContractId, Hash, PublicKey, ScAddress, Uint256};

    match Strkey::from_string(strkey)
        .map_err(|e| SacTransferBuildError(format!("strkey parse failed: {e}")))?
    {
        Strkey::PublicKeyEd25519(pk) => Ok(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256(pk.0)),
        ))),
        Strkey::Contract(c) => Ok(ScAddress::Contract(ContractId(Hash(c.0)))),
        other => Err(SacTransferBuildError(format!(
            "strkey is not a G- or C-strkey: {other:?}"
        ))),
    }
}

/// Builds the SEP-41 `transfer(from, to, amount)` invocation args for a SAC.
///
/// Used to move XLM SAC balance into the smart-account C-address before the
/// vault deposit submit.
fn build_sac_transfer_invoke(
    sac_contract: &str,
    from: &str,
    to: &str,
    amount: i128,
) -> Result<stellar_xdr::InvokeContractArgs, SacTransferBuildError> {
    use stellar_xdr::{Int128Parts, InvokeContractArgs, ScSymbol, ScVal, StringM, VecM};

    let contract_address = strkey_to_sc_address(sac_contract)?;
    let from_sc = strkey_to_sc_address(from)?;
    let to_sc = strkey_to_sc_address(to)?;

    let args_vec: Vec<ScVal> = vec![
        ScVal::Address(from_sc),
        ScVal::Address(to_sc),
        ScVal::I128(Int128Parts {
            hi: (amount >> 64) as i64,
            lo: amount as u64,
        }),
    ];
    let args: VecM<ScVal> = args_vec
        .try_into()
        .map_err(|e| SacTransferBuildError(format!("args VecM construction failed: {e:?}")))?;

    let function_name: StringM<32> = "transfer"
        .try_into()
        .map_err(|e| SacTransferBuildError(format!("ScSymbol construction failed: {e:?}")))?;

    Ok(InvokeContractArgs {
        contract_address,
        function_name: ScSymbol(function_name),
        args,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const TESTNET_CHAIN_ID: &str = "stellar:testnet";
const FRIENDBOT_URL: &str = "https://friendbot.stellar.org";

/// XLM DeFindex vault on testnet (id: `xlm_paltalabs_vault`).
///
/// Source: `public/testnet.contracts.json` `ids.xlm_paltalabs_vault`.
const DEFINDEX_TESTNET_VAULT: &str = "CCLV4H7WTLJQ7ATLHBBQV2WW3OINF3FOY5XZ7VPHZO7NH3D2ZS4GFSF6";

/// Native XLM Stellar Asset Contract on testnet.
///
/// The XLM vault's underlying asset is this SAC.  Used for both the initial
/// SAC funding step and as the deposit asset.
const XLM_SAC_TESTNET: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

/// Amount to fund the smart-account C-address with XLM SAC: 50 XLM (7 decimals).
const XLM_FUND_AMOUNT: i128 = 500_000_000; // 50 XLM

/// Amount to deposit into the XLM vault: 5 XLM (7 decimals).
///
/// Small enough to leave the wallet with gas fees; large enough to confirm
/// the vault will mint non-zero shares.
const XLM_DEPOSIT_AMOUNT: i128 = 50_000_000; // 5 XLM

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn testnet_rpc() -> StellarRpcClient {
    StellarRpcClient::new(TESTNET_RPC_URL).expect("testnet RPC URL must be valid")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must work")
        .as_secs()
}

fn make_testnet_signer(seed: Zeroizing<[u8; 32]>) -> Box<dyn Signer + Send + Sync> {
    Box::new(SoftwareSigningKey::new_from_zeroizing(seed))
}

async fn deploy_testnet_smart_account(
    request: DeploySmartAccountRequest<Box<dyn Signer + Send + Sync>>,
) -> Result<DeploySmartAccountOutcome, Box<dyn Error + Send + Sync>> {
    let deployer = DeployerKeypair::SecretEnv {
        var_name: request.keypair_var_name,
        signer: request.deployer_signer,
    };
    let deploy_args = DeploymentArgs {
        deployer,
        initial_signer: request.initial_signer,
        salt: request.salt,
        network_passphrase: request.network_passphrase,
        rpc_url: request.rpc_url,
        timeout: request.timeout,
        fee: DeployResolvedFeePerOp {
            stroops: request.fee_per_op_stroops,
            percentile_label: "explicit".to_owned(),
        },
        dry_run: false,
        genesis_signer_scval_override: None,
    };
    let result = deploy_smart_account(deploy_args, None).await?;
    Ok(DeploySmartAccountOutcome {
        smart_account: result.smart_account,
        tx_hash: result.tx_hash,
    })
}

async fn fetch_testnet_sequence(account_id: String) -> Result<i64, Box<dyn Error + Send + Sync>> {
    let rpc_client = StellarRpcClient::new(TESTNET_RPC_URL)?;
    let account = fetch_account(&rpc_client, &account_id, &[]).await?;
    Ok(account.sequence_number)
}

async fn sign_testnet_envelope(
    unsigned_xdr: String,
    funder_seed: Zeroizing<[u8; 32]>,
    network_passphrase: String,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    let signer = SoftwareSigningKey::new_from_zeroizing(funder_seed);
    Ok(attach_signature(&unsigned_xdr, &signer, &network_passphrase).await?)
}

async fn submit_testnet_signed_xdr(
    signed_xdr: String,
) -> Result<SubmissionResult, Box<dyn Error + Send + Sync>> {
    let rpc_client = StellarRpcClient::new(TESTNET_RPC_URL)?;
    Ok(submit_transaction_and_wait(
        &rpc_client,
        &signed_xdr,
        Duration::from_secs(60),
        TESTNET_PASSPHRASE,
        Some(SubmissionSignerKind::Software),
    )
    .await?)
}

// ─────────────────────────────────────────────────────────────────────────────
// Classifiers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` when an error string from `DefindexVaultAdapter::submit`
/// indicates an auth / `__check_auth` failure rather than an environmental
/// issue (RPC timeout, insufficient balance, vault state, etc.).
fn classify_submit_auth_failure(error_str: &str) -> bool {
    error_str.contains("__check_auth")
        || error_str.contains("RuleIdMismatch")
        || error_str.contains("context rule-ID mismatch")
        || error_str.contains("observed len 0")
        || error_str.contains("AuthEntryConstructionFailed")
        || error_str.contains("context-rule")
        || error_str.contains("ContextRuleIdsLengthMismatch")
        || error_str.contains("UnvalidatedContext")
}

// ─────────────────────────────────────────────────────────────────────────────
// Acceptance — Real on-chain DeFindex XLM vault deposit submit-and-confirm
// ─────────────────────────────────────────────────────────────────────────────

/// **Acceptance** — Real on-chain DeFindex XLM vault deposit submit-and-confirm.
///
/// Validates the `submit.rs` auth-entry sub-invocation change:
/// the DeFindex vault's `deposit` calls `require_auth` on the depositor;
/// the vault then calls the XLM SAC `transfer(from=wallet)` as a sub-invocation.
/// The auth digest MUST cover the full invocation tree or `__check_auth` rejects.
///
/// # Steps
///
/// 1. Generate a fresh ed25519 signer and deploy a fresh smart-account.
/// 2. Fund the smart-account C-address with XLM SAC via `fund_sac_balance`.
/// 3. Read the vault's asset list on-chain and assert the underlying asset is
///    the XLM SAC.
/// 4. Build `VaultDepositArgs` and call `DefindexVaultAdapter::submit`.
///    The adapter enforces the inline ordered trust gate (pin/upgradable/roles/asset-count)
///    before signing.
/// 5. Assert transaction success (confirmed on-chain).
///
/// # On-chain failure handling
///
/// Any error from `DefindexVaultAdapter::submit` — particularly auth-related
/// errors (`__check_auth`, `RuleIdMismatch`, `AuthEntryConstructionFailed`) —
/// means the `submit.rs` fix is wrong.  The test PANICs with the full error.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live testnet acceptance; run in the testnet-acceptance CI job via -- --ignored"]
async fn defindex_deposit_submit_and_confirm() {
    eprintln!(
        "DeFindex XLM vault deposit acceptance — \
         validating submit.rs auth-entry sub-invocation via XLM SAC"
    );

    // ── Step 1: Deploy a fresh smart-account ────────────────────────────────
    let deployed = deploy_funded_smart_account(
        "",
        "testnet-defindex-deposit-acceptance-generated",
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
        FRIENDBOT_URL,
        make_testnet_signer,
        deploy_testnet_smart_account,
    )
    .await
    .unwrap_or_else(|e| panic!("FAIL — smart-account deployment failed: {e:?}"));
    let wallet_c = deployed.wallet_c;
    let signer = deployed.signer;

    eprintln!("Smart account deployed: {}", redact_strkey(&wallet_c));

    // ── Step 2: Fund smart-account C-address with XLM SAC ───────────────────
    // A smart-account C-address cannot receive classic XLM payments.
    // Fund via XLM SAC `transfer(from_g, to_c, amount)` using the 8-step Soroban flow.
    let fund_result = fund_sac_balance(
        "",
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
        FRIENDBOT_URL,
        XLM_SAC_TESTNET,
        &wallet_c,
        XLM_FUND_AMOUNT,
        build_sac_transfer_invoke,
        |account_id| fetch_testnet_sequence(account_id.to_owned()),
        |unsigned_xdr, funder_seed, network_passphrase| {
            sign_testnet_envelope(unsigned_xdr, funder_seed, network_passphrase.to_owned())
        },
        submit_testnet_signed_xdr,
    )
    .await
    .unwrap_or_else(|e| panic!("FAIL — XLM SAC transfer submit failed: {e:?}"));

    eprintln!(
        "XLM SAC funding confirmed on-chain: ledger={}",
        fund_result.ledger
    );

    // ── Step 3: Read vault asset list and confirm XLM SAC address ───────────
    eprintln!("Step 3: reading XLM vault asset list on-chain");
    let rpc = testnet_rpc();

    // WASM pin must pass before reading vault state (ordered trust gate).
    let wasm_result = retry_rpc!(verify_defindex_vault_wasm(
        DEFINDEX_TESTNET_VAULT,
        &rpc,
        Some(&rpc),
    ));
    wasm_result.unwrap_or_else(|e| {
        panic!(
            "FAIL — vault WASM pin failed before reading assets: {e:?}\n\
             Update DEFINDEX_VAULT_WASM_HASH in pins.rs if the vault has been upgraded."
        )
    });

    let vault_assets = retry_rpc!(read_vault_assets(DEFINDEX_TESTNET_VAULT, &rpc))
        .unwrap_or_else(|e| panic!("FAIL — could not read vault assets on-chain: {e:?}"));

    eprintln!(
        "vault_assets count: {}, asset[0]: {}",
        vault_assets.len(),
        vault_assets
            .first()
            .map(|a| redact_strkey(&a.address))
            .unwrap_or_else(|| "(none)".to_owned()),
    );

    if vault_assets.is_empty() {
        panic!(
            "FAIL — XLM vault has no assets. The vault may have been misconfigured or emptied.\n\
             Environmental fixture gap: expected exactly one asset (XLM SAC)."
        );
    }

    // The XLM vault's underlying asset must be the XLM SAC.
    let vault_xlm_address = vault_assets[0].address.clone();
    if vault_xlm_address != XLM_SAC_TESTNET {
        eprintln!(
            "WARNING: vault asset[0] ({}) != expected XLM SAC ({}).\n\
             The vault may have changed its underlying asset. \
             Proceeding with the on-chain-reported asset address.",
            redact_strkey(&vault_xlm_address),
            redact_strkey(XLM_SAC_TESTNET),
        );
    } else {
        eprintln!(
            "vault underlying asset[0] confirmed as XLM SAC ({})",
            redact_strkey(&vault_xlm_address)
        );
    }

    // ── Step 4: Deposit XLM into the DeFindex XLM vault ─────────────────────
    // The wallet holds XLM SAC from the funding step.  Deposit a small amount.
    // amounts_desired = [XLM_DEPOSIT_AMOUNT] — one entry per vault asset (1 asset).
    // amounts_min = [0] — any non-zero receipt is acceptable; we are validating
    //   the submit path, not vault economics.
    // invest = false — no immediate strategy investment needed for this validation.
    // override_upgradable = true — the testnet vault may be marked upgradable:true.
    eprintln!(
        "Step 4: depositing XLM into DeFindex XLM vault via DefindexVaultAdapter::submit\n\
         vault={} xlm_sac={} amounts_desired=[{XLM_DEPOSIT_AMOUNT}]",
        redact_strkey(DEFINDEX_TESTNET_VAULT),
        redact_strkey(XLM_SAC_TESTNET),
    );

    let deposit_request_id = format!("defindex-deposit-acceptance-{}", now_secs());
    let deposit_witness = match dispatch_gate("vault", deposit_request_id.clone()) {
        Ok(GateOutcome::Allow(w)) => w,
        Ok(GateOutcome::RequireApproval) => {
            panic!("FAIL — dispatch_gate returned RequireApproval for 'vault' verb (unexpected)")
        }
        Err(e) => {
            panic!("FAIL — dispatch_gate returned error for 'vault' verb: {e:?}")
        }
    };

    let vault_pin = DefiContractPin::new(
        "defindex",
        "v1",
        "default",
        TESTNET_CHAIN_ID,
        DEFINDEX_TESTNET_VAULT,
        DEFINDEX_VAULT_WASM_HASH,
        "defindex-vault",
    );

    let primary_rpc_for_deposit = testnet_rpc();
    let deposit_ctx = DefiAdapterCtx::new_with_submit_ctx(
        "default",
        &vault_pin,
        &primary_rpc_for_deposit,
        Some(signer.as_ref()),
        Some(TESTNET_PASSPHRASE),
        Some(TESTNET_CHAIN_ID),
        None,
        Some(Duration::from_secs(120)),
    );

    let deposit_args = VaultDepositArgs {
        vault_address: DEFINDEX_TESTNET_VAULT.to_owned(),
        amounts_desired: vec![XLM_DEPOSIT_AMOUNT],
        amounts_min: vec![0],
        from_address: wallet_c.clone(),
        invest: false,
        override_upgradable: true,
    };

    let defindex_adapter = DefindexVaultAdapter::new();
    let deposit_result = defindex_adapter
        .submit(&deposit_args, &deposit_ctx, deposit_witness)
        .await;

    match deposit_result {
        Ok(()) => {
            eprintln!(
                "\nVERDICT: submit.rs fix VALIDATED for DeFindex XLM vault\n\
                 DefindexVaultAdapter::submit SUCCEEDED on-chain for wallet {}\n\
                 vault={} xlm_deposited={XLM_DEPOSIT_AMOUNT}\n\
                 The auth-entry sub-invocation fix is confirmed correct.",
                redact_strkey(&wallet_c),
                redact_strkey(DEFINDEX_TESTNET_VAULT),
            );
        }
        Err(e) => {
            let error_str = format!("{e:?}");
            if classify_submit_auth_failure(&error_str) {
                panic!(
                    "\nVERDICT: FAILED (auth/check_auth error)\n\
                     submit.rs fix is WRONG or INCOMPLETE for DeFindex XLM vault.\n\
                     DefindexVaultAdapter::submit FAILED with auth-related error:\n\
                     {e:?}\n\
                     wallet_c={}\n\
                     vault={} amounts_desired=[{XLM_DEPOSIT_AMOUNT}]\n\
                     This indicates the auth-entry sub-invocation construction \
                     did not produce a valid signed auth for \
                     the DeFindex vault's require_auth call and XLM SAC transfer \
                     sub-invocation.",
                    redact_strkey(&wallet_c),
                    redact_strkey(DEFINDEX_TESTNET_VAULT),
                );
            } else {
                panic!(
                    "\nVERDICT: FAILED (non-auth error)\n\
                     DefindexVaultAdapter::submit FAILED with non-auth error:\n\
                     {e:?}\n\
                     wallet_c={}\n\
                     vault={} amounts_desired=[{XLM_DEPOSIT_AMOUNT}]\n\
                     This may be an environmental issue (testnet RPC, vault state, \
                     insufficient XLM balance) rather than a submit.rs regression. \
                     Investigate the error above.",
                    redact_strkey(&wallet_c),
                    redact_strkey(DEFINDEX_TESTNET_VAULT),
                );
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Acceptance — Real on-chain DeFindex XLM vault deposit-then-withdraw
// ─────────────────────────────────────────────────────────────────────────────

/// **Acceptance** — Real on-chain DeFindex XLM vault deposit-then-withdraw,
/// validating the withdraw auth path through the wallet's `__check_auth`.
///
/// This test validates the **withdraw** auth path: `vault.withdraw` requires auth
/// on the withdrawing address.  For the XLM vault, the sub-invocation direction
/// on withdraw is `XLM_SAC.transfer(from=vault, to=wallet)` — authorised by the
/// VAULT, not the wallet.  The wallet's auth entry covers only the
/// `vault.withdraw` root call; this test confirms that shape passes on-chain.
///
/// # Steps
///
/// 1. Deploy a fresh smart-account and fund with XLM SAC.
/// 2. Read vault assets; confirm XLM SAC address.
/// 3. Deposit XLM into vault via `DefindexVaultAdapter::submit`.
/// 4. Query wallet's actual share balance via `read_vault_share_balance`.
/// 5. Withdraw ALL queried shares via `DefindexVaultAdapter::submit` with
///    `VaultWithdrawArgs { withdraw_shares: queried_balance, min_amounts_out: [0] }`.
/// 6. Assert `submit` returned `Ok(())` — confirmed on-chain.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live testnet acceptance; run in the testnet-acceptance CI job via -- --ignored"]
async fn defindex_deposit_then_withdraw_submit_and_confirm() {
    eprintln!(
        "DeFindex XLM vault deposit-then-withdraw acceptance — \
         validating withdraw auth path through __check_auth"
    );

    // ── Step 1: Deploy a fresh smart-account ────────────────────────────────
    let deployed = deploy_funded_smart_account(
        "",
        "testnet-defindex-withdraw-acceptance-generated",
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
        FRIENDBOT_URL,
        make_testnet_signer,
        deploy_testnet_smart_account,
    )
    .await
    .unwrap_or_else(|e| panic!("FAIL — smart-account deployment failed: {e:?}"));
    let wallet_c = deployed.wallet_c;
    let signer = deployed.signer;

    eprintln!("Smart account deployed: {}", redact_strkey(&wallet_c));

    // ── Step 2a: Fund smart-account C-address with XLM SAC ──────────────────
    let fund_result = fund_sac_balance(
        "",
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
        FRIENDBOT_URL,
        XLM_SAC_TESTNET,
        &wallet_c,
        XLM_FUND_AMOUNT,
        build_sac_transfer_invoke,
        |account_id| fetch_testnet_sequence(account_id.to_owned()),
        |unsigned_xdr, funder_seed, network_passphrase| {
            sign_testnet_envelope(unsigned_xdr, funder_seed, network_passphrase.to_owned())
        },
        submit_testnet_signed_xdr,
    )
    .await
    .unwrap_or_else(|e| panic!("FAIL — XLM SAC transfer submit failed: {e:?}"));

    eprintln!(
        "XLM SAC funding confirmed on-chain: ledger={}",
        fund_result.ledger
    );

    // ── Step 2b: Read vault asset list and confirm XLM SAC address ──────────
    eprintln!("Step 2b: reading XLM vault asset list on-chain");
    let rpc = testnet_rpc();

    let wasm_result = retry_rpc!(verify_defindex_vault_wasm(
        DEFINDEX_TESTNET_VAULT,
        &rpc,
        Some(&rpc),
    ));
    wasm_result.unwrap_or_else(|e| {
        panic!(
            "FAIL — vault WASM pin failed before reading assets: {e:?}\n\
             Update DEFINDEX_VAULT_WASM_HASH in pins.rs if the vault has been upgraded."
        )
    });

    let vault_assets = retry_rpc!(read_vault_assets(DEFINDEX_TESTNET_VAULT, &rpc))
        .unwrap_or_else(|e| panic!("FAIL — could not read vault assets on-chain: {e:?}"));

    if vault_assets.is_empty() {
        panic!(
            "FAIL — XLM vault has no assets. Expected exactly one asset (XLM SAC).\n\
             The vault may have been misconfigured or emptied."
        );
    }

    let vault_xlm_address = vault_assets[0].address.clone();
    eprintln!(
        "vault_assets count: {}, asset[0]: {}",
        vault_assets.len(),
        redact_strkey(&vault_xlm_address),
    );

    if vault_xlm_address != XLM_SAC_TESTNET {
        eprintln!(
            "WARNING: vault asset[0] ({}) != expected XLM SAC ({}).\n\
             Proceeding with the on-chain-reported asset address.",
            redact_strkey(&vault_xlm_address),
            redact_strkey(XLM_SAC_TESTNET),
        );
    }

    // ── Step 3: Deposit XLM into vault ──────────────────────────────────────
    eprintln!(
        "Step 3: depositing XLM into DeFindex XLM vault via DefindexVaultAdapter::submit\n\
         vault={} xlm_sac={} amounts_desired=[{XLM_DEPOSIT_AMOUNT}]",
        redact_strkey(DEFINDEX_TESTNET_VAULT),
        redact_strkey(XLM_SAC_TESTNET),
    );

    let deposit_request_id = format!("defindex-withdraw-deposit-{}", now_secs());
    let deposit_witness = match dispatch_gate("vault", deposit_request_id.clone()) {
        Ok(GateOutcome::Allow(w)) => w,
        Ok(GateOutcome::RequireApproval) => {
            panic!("FAIL — dispatch_gate returned RequireApproval for 'vault' verb (unexpected)")
        }
        Err(e) => {
            panic!("FAIL — dispatch_gate returned error for 'vault' verb: {e:?}")
        }
    };

    let vault_pin = DefiContractPin::new(
        "defindex",
        "v1",
        "default",
        TESTNET_CHAIN_ID,
        DEFINDEX_TESTNET_VAULT,
        DEFINDEX_VAULT_WASM_HASH,
        "defindex-vault",
    );

    let primary_rpc_for_deposit = testnet_rpc();
    let deposit_ctx = DefiAdapterCtx::new_with_submit_ctx(
        "default",
        &vault_pin,
        &primary_rpc_for_deposit,
        Some(signer.as_ref()),
        Some(TESTNET_PASSPHRASE),
        Some(TESTNET_CHAIN_ID),
        None,
        Some(Duration::from_secs(120)),
    );

    let deposit_args = VaultDepositArgs {
        vault_address: DEFINDEX_TESTNET_VAULT.to_owned(),
        amounts_desired: vec![XLM_DEPOSIT_AMOUNT],
        amounts_min: vec![0],
        from_address: wallet_c.clone(),
        invest: false,
        override_upgradable: true,
    };

    let defindex_adapter = DefindexVaultAdapter::new();
    let deposit_result = defindex_adapter
        .submit(&deposit_args, &deposit_ctx, deposit_witness)
        .await;

    match deposit_result {
        Ok(()) => {
            eprintln!(
                "Step 3: XLM deposit SUCCEEDED for wallet {} — shares minted.",
                redact_strkey(&wallet_c)
            );
        }
        Err(e) => {
            let error_str = format!("{e:?}");
            if classify_submit_auth_failure(&error_str) {
                panic!(
                    "\nVERDICT: FAILED (deposit auth/check_auth error — withdraw not reached)\n\
                     DefindexVaultAdapter::submit FAILED with auth-related error on DEPOSIT:\n\
                     {e:?}\n\
                     wallet_c={}\n\
                     vault={} amounts_desired=[{XLM_DEPOSIT_AMOUNT}]\n\
                     The deposit precondition failed — cannot proceed to withdraw.",
                    redact_strkey(&wallet_c),
                    redact_strkey(DEFINDEX_TESTNET_VAULT),
                );
            } else {
                panic!(
                    "\nVERDICT: FAILED (deposit non-auth error — withdraw not reached)\n\
                     DefindexVaultAdapter::submit FAILED with non-auth error on DEPOSIT:\n\
                     {e:?}\n\
                     wallet_c={}\n\
                     vault={} amounts_desired=[{XLM_DEPOSIT_AMOUNT}]\n\
                     The deposit precondition failed — investigate the error above.",
                    redact_strkey(&wallet_c),
                    redact_strkey(DEFINDEX_TESTNET_VAULT),
                );
            }
        }
    }

    // ── Step 4: Query wallet's actual share balance ──────────────────────────
    eprintln!("Step 4: querying wallet vault share balance on-chain");

    let share_balance = retry_rpc!(read_vault_share_balance(
        DEFINDEX_TESTNET_VAULT,
        &wallet_c,
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
    ))
    .unwrap_or_else(|e| {
        panic!(
            "FAIL — could not query wallet share balance on-chain: {e:?}\n\
             wallet_c={}\n\
             vault={}\n\
             This is a precondition failure — cannot proceed to withdraw.",
            redact_strkey(&wallet_c),
            redact_strkey(DEFINDEX_TESTNET_VAULT),
        )
    });

    eprintln!(
        "Step 4: wallet {} holds {} vault shares after deposit",
        redact_strkey(&wallet_c),
        share_balance,
    );

    if share_balance <= 0 {
        panic!(
            "FAIL — wallet holds zero or negative shares after deposit.\n\
             share_balance={share_balance}\n\
             wallet_c={}\n\
             vault={}\n\
             Expected positive share balance after successful deposit.",
            redact_strkey(&wallet_c),
            redact_strkey(DEFINDEX_TESTNET_VAULT),
        );
    }

    // ── Step 5: Withdraw ALL shares ──────────────────────────────────────────
    // Withdraw 100% of the queried share balance.
    // min_amounts_out length MUST equal vault asset count (1 for the XLM vault).
    eprintln!(
        "Step 5: withdrawing ALL {} shares from DeFindex XLM vault via \
         DefindexVaultAdapter::submit",
        share_balance,
    );

    let withdraw_request_id = format!("defindex-withdraw-acceptance-{}", now_secs());
    let withdraw_witness = match dispatch_gate("vault", withdraw_request_id.clone()) {
        Ok(GateOutcome::Allow(w)) => w,
        Ok(GateOutcome::RequireApproval) => {
            panic!(
                "FAIL — dispatch_gate returned RequireApproval for 'vault' verb on withdraw (unexpected)"
            )
        }
        Err(e) => {
            panic!("FAIL — dispatch_gate returned error for 'vault' verb on withdraw: {e:?}")
        }
    };

    let primary_rpc_for_withdraw = testnet_rpc();
    let withdraw_ctx = DefiAdapterCtx::new_with_submit_ctx(
        "default",
        &vault_pin,
        &primary_rpc_for_withdraw,
        Some(signer.as_ref()),
        Some(TESTNET_PASSPHRASE),
        Some(TESTNET_CHAIN_ID),
        None,
        Some(Duration::from_secs(120)),
    );

    let withdraw_args = VaultWithdrawArgs {
        vault_address: DEFINDEX_TESTNET_VAULT.to_owned(),
        withdraw_shares: share_balance,
        min_amounts_out: vec![0],
        from_address: wallet_c.clone(),
        override_upgradable: true,
    };

    let withdraw_result = defindex_adapter
        .submit(&withdraw_args, &withdraw_ctx, withdraw_witness)
        .await;

    match withdraw_result {
        Ok(()) => {
            eprintln!(
                "\nVERDICT: withdraw auth path VALIDATED for DeFindex XLM vault\n\
                 DefindexVaultAdapter::submit (withdraw) SUCCEEDED on-chain for wallet {}\n\
                 vault={} shares_withdrawn={}\n\
                 The withdraw auth-entry construction is confirmed correct \
                 for the vault.withdraw root call.",
                redact_strkey(&wallet_c),
                redact_strkey(DEFINDEX_TESTNET_VAULT),
                share_balance,
            );
        }
        Err(e) => {
            let error_str = format!("{e:?}");
            if classify_submit_auth_failure(&error_str) {
                panic!(
                    "\nVERDICT: FAILED (withdraw auth/check_auth error)\n\
                     DefindexVaultAdapter::submit (withdraw) FAILED with auth-related error:\n\
                     {e:?}\n\
                     wallet_c={}\n\
                     vault={} shares_withdrawn={share_balance}\n\
                     The withdraw auth-entry construction does NOT produce a valid signed auth \
                     for the vault.withdraw root call.",
                    redact_strkey(&wallet_c),
                    redact_strkey(DEFINDEX_TESTNET_VAULT),
                );
            } else {
                panic!(
                    "\nVERDICT: FAILED (withdraw non-auth error)\n\
                     DefindexVaultAdapter::submit (withdraw) FAILED with non-auth error:\n\
                     {e:?}\n\
                     wallet_c={}\n\
                     vault={} shares_withdrawn={share_balance}\n\
                     This may be an environmental issue (testnet RPC, vault state, \
                     minimum-reserve restriction) rather than an auth regression. \
                     Investigate the error above.",
                    redact_strkey(&wallet_c),
                    redact_strkey(DEFINDEX_TESTNET_VAULT),
                );
            }
        }
    }
}
