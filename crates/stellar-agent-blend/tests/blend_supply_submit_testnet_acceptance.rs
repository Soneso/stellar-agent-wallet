//! Testnet acceptance test for the Blend supply `submit_signed_invoke` path.
//!
//! Gated behind the `testnet-acceptance` feature flag:
//!
//! ```text
//! cargo test -p stellar-agent-blend --features testnet-acceptance \
//!   --test blend_supply_submit_testnet_acceptance
//! ```
//!
//! # Purpose
//!
//! Validates that a Blend `supply` produces a signed auth entry whose digest
//! covers the full invocation tree, so the pool's `require_auth` and the
//! underlying SAC `transfer` sub-invocation are authorised on-chain.
//!
//! A Blend `supply` call moves XLM SAC balance from the wallet C-address into
//! the pool, exercising the external-contract auth path where:
//!   - The pool's `submit` calls `e.current_contract_address().require_auth()`
//!     on the wallet's behalf (NOT the wallet calling it directly).
//!   - The underlying SAC `transfer` is a sub-invocation.
//!
//! # Acceptance criteria
//!
//! - **This test** — Deploy a fresh smart-account, fund its XLM SAC
//!   balance via the 8-step Soroban flow, read the pool's reserve list to
//!   find the XLM SAC reserve, supply a small amount, confirm the transaction
//!   on-chain.  Report the redacted tx hash + ledger.
//!
//! # On-chain failure semantics
//!
//! If `BlendLendAdapter::submit` returns an error, particularly one containing
//! `__check_auth`, `RuleIdMismatch`, `AuthEntryConstructionFailed`, or
//! `context-rule`, the signed auth entry did not cover the full invocation
//! tree.  The test reports the exact error and PANICs — it does NOT paper over
//! failures.
//!
//! # What this file verifies
//!
//! The signed auth entry covers the require_auth + SAC-transfer sub-invocation,
//! the ordered trust gate on the supply path, and a Blend supply with XLM
//! confirmed on-chain.

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

use stellar_agent_blend::{
    abi::{BlendRequest, LendArgs, RequestType},
    adapter::BlendLendAdapter,
    oracle_fetch::read_pool_reserve_list,
    pins::BLEND_V2_POOL_WASM_HASH_TESTNET,
};
use stellar_agent_defi::{
    adapter::{DefiAdapter, DefiAdapterCtx},
    dispatch::{GateOutcome, dispatch_gate},
    pins::DefiContractPin,
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
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const TESTNET_CHAIN_ID: &str = "stellar:testnet";
const FRIENDBOT_URL: &str = "https://friendbot.stellar.org";

/// The Blend v2 testnet pool address.
const BLEND_V2_TESTNET_POOL: &str = "CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF";

/// XLM SAC on testnet.
///
/// Verified at stellar-agent-dex/src/sac.rs KAT test and
/// `soroswap-core/public/testnet.contracts.json`.
const XLM_SAC_TESTNET: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

/// Amount to fund the smart-account with: 20 XLM in stroops (7 decimals).
const FUND_AMOUNT: i128 = 200_000_000; // 20 XLM

/// Amount to supply to the Blend pool: 1 XLM.
const SUPPLY_AMOUNT: i128 = 10_000_000; // 1 XLM

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned by the local SAC-transfer-invoke builder.
#[derive(Debug)]
struct SacTransferBuildError(String);

impl std::fmt::Display for SacTransferBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SAC transfer build failed: {}", self.0)
    }
}

impl Error for SacTransferBuildError {}

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
/// Test-only funding helper that moves XLM SAC balance into the smart-account
/// C-address before the supply submit.
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

/// Spy [`stellar_agent_network::SequenceFloorHook`] standing in for
/// `stellar-agent-mcp`'s process-local `SequenceFloorTracker`.
///
/// Records every `record_confirmed` call so this test can assert, against a
/// REAL confirmed on-chain submit, that `BlendLendAdapter::submit` ->
/// `submit_signed_invoke` threads `DefiAdapterCtx::sequence_floor` through to
/// `SubmitInvokeArgs::sequence_floor` and invokes it exactly as the MCP tool
/// layer's classic commit verbs invoke their own tracker.
#[derive(Default)]
struct SequenceFloorSpy {
    recorded: std::sync::Mutex<Vec<(String, i64)>>,
}

#[async_trait::async_trait]
impl stellar_agent_network::SequenceFloorHook for SequenceFloorSpy {
    async fn floor(&self, _account_id: &str) -> Option<i64> {
        // No floor recorded yet in this fresh spy — the pre-submit fetch
        // proceeds without a catch-up poll, exactly like a first call in a
        // freshly started MCP server.
        None
    }

    async fn record_confirmed(&self, account_id: &str, consumed_sequence: i64) {
        self.recorded
            .lock()
            .expect("lock")
            .push((account_id.to_owned(), consumed_sequence));
    }
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
// Acceptance — Real on-chain Blend supply submit-and-confirm
// ─────────────────────────────────────────────────────────────────────────────

/// **Acceptance** — Real on-chain Blend supply submit-and-confirm.
///
/// Validates the auth-entry sub-invocation handling: the Blend pool's
/// `submit` calls `require_auth` on the wallet contract;
/// the pool then calls `SAC.transfer(from=wallet)` as a sub-invocation.
/// The auth digest MUST cover the full invocation tree or `__check_auth` rejects.
///
/// # Steps
///
/// 1. Generate a fresh ed25519 signer and deploy a fresh smart-account using a
///    Friendbot-funded deployer.
/// 2. Fund the smart-account C-address with XLM SAC balance via the 8-step
///    Soroban flow (`build_sac_transfer_invoke`).
/// 3. Read the pool's reserve list to confirm XLM SAC is a reserve.
/// 4. Build `LendArgs` with a `Supply` request for the XLM SAC.
/// 5. Call `BlendLendAdapter::submit` with a `dispatch_gate` witness.
/// 6. Assert transaction success (confirmed on-chain).
///
/// # On-chain failure handling
///
/// Any error returned by `BlendLendAdapter::submit` — particularly one
/// containing `__check_auth`, `AuthEntryConstructionFailed`, `RuleIdMismatch`,
/// or `DeploymentFailed` — means the signed auth entry is wrong.  The test
/// PANICs with the full error; it does NOT fail-soft or skip.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live testnet acceptance; run in the testnet-acceptance CI job via -- --ignored"]
async fn blend_supply_submit_and_confirm() {
    eprintln!("Blend supply acceptance — validating the auth-entry sub-invocation handling");

    let deployed = deploy_funded_smart_account(
        "",
        "testnet-blend-supply-acceptance-generated",
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
        FRIENDBOT_URL,
        make_testnet_signer,
        deploy_testnet_smart_account,
    )
    .await
    .unwrap_or_else(|e| panic!("FAIL — smart-account deployment failed: {e:?}"));
    let wallet_c = deployed.wallet_c;
    let signer_g = deployed.signer_g_strkey;
    let signer = deployed.signer;

    // ── Step 3: Fund smart-account C-address with XLM SAC balance ────────────
    // A smart-account C-address cannot receive classic XLM payments.
    // Must call XLM SAC `transfer(from_g, to_c, amount)` via 8-step Soroban flow.
    // Pattern sourced from: dex_swap_testnet_acceptance.rs Step 3.
    let fund_result = fund_sac_balance(
        "",
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
        FRIENDBOT_URL,
        XLM_SAC_TESTNET,
        &wallet_c,
        FUND_AMOUNT,
        build_sac_transfer_invoke,
        |account_id| fetch_testnet_sequence(account_id.to_owned()),
        |unsigned_xdr, funder_seed, network_passphrase| {
            sign_testnet_envelope(unsigned_xdr, funder_seed, network_passphrase.to_owned())
        },
        submit_testnet_signed_xdr,
    )
    .await
    .unwrap_or_else(|e| panic!("FAIL — SAC transfer submit failed: {e:?}"));

    eprintln!(
        "XLM SAC funding confirmed on-chain: ledger={}",
        fund_result.ledger
    );

    // ── Step 4: Read pool reserve list and confirm XLM SAC is a reserve ──────
    eprintln!("Step 4: reading pool reserve list");
    let rpc = testnet_rpc();
    let reserve_list = retry_rpc!(read_pool_reserve_list(BLEND_V2_TESTNET_POOL, &rpc))
        .unwrap_or_else(|e| {
            panic!(
                "FAIL — could not read pool reserve list: {e:?}\n\
                 This is a hard failure; testnet-acceptance requires live connectivity."
            )
        });

    eprintln!("pool reserve list: {reserve_list:?}");

    // Confirm XLM SAC is in the reserve list.
    // The Blend v2 testnet pool includes XLM as a reserve (verified on-chain 2026-06-04).
    let xlm_sac_is_reserve = reserve_list.iter().any(|addr| addr == XLM_SAC_TESTNET);

    if !xlm_sac_is_reserve {
        // If XLM SAC is not in the reserve list, attempt with the first available reserve.
        // Document the fixture state so this can be debugged.
        eprintln!(
            "NOTE: XLM SAC ({}) is NOT in the reserve list.\n\
             Reserve list: {reserve_list:?}\n\
             Attempting supply with first available reserve or FAILING if list is empty.",
            redact_strkey(XLM_SAC_TESTNET)
        );

        if reserve_list.is_empty() {
            panic!(
                "FAIL — Blend testnet pool has no reserves. \
                 Cannot exercise the supply path. \
                 Environmental fixture gap: the pool has been emptied or misconfigured."
            );
        }
    }

    // Pick the supply asset: XLM SAC if available, otherwise first reserve.
    let supply_asset = if xlm_sac_is_reserve {
        eprintln!(
            "XLM SAC confirmed as reserve: {}",
            redact_strkey(XLM_SAC_TESTNET)
        );
        XLM_SAC_TESTNET.to_owned()
    } else {
        let first = reserve_list[0].clone();
        eprintln!(
            "Using first pool reserve as supply asset (XLM SAC not in list): {}",
            redact_strkey(&first)
        );
        first
    };

    // If we are not supplying XLM SAC, the wallet won't have a balance of the
    // other reserve asset; document this blocker.
    if supply_asset != XLM_SAC_TESTNET {
        panic!(
            "FAIL — supply asset ({}) is not XLM SAC.\n\
             The wallet was funded with XLM SAC only. Supplying a different \
             reserve requires a separate funding step for that asset, which is \
             not implemented in this test.\n\
             Environmental fixture gap: the testnet pool's reserve list has changed \
             (expected XLM SAC = {} to be present).",
            redact_strkey(&supply_asset),
            redact_strkey(XLM_SAC_TESTNET)
        );
    }

    // ── Step 5: Execute the real on-chain supply via BlendLendAdapter::submit ─
    eprintln!(
        "Step 5: executing real on-chain Blend supply via BlendLendAdapter::submit\n\
         supply_asset={} amount={}",
        redact_strkey(&supply_asset),
        SUPPLY_AMOUNT
    );

    // Build the dispatch gate witness for the "lend" verb.
    let request_id = format!("blend-supply-acceptance-{}", now_secs());
    let witness = match dispatch_gate("lend", request_id.clone()) {
        Ok(GateOutcome::Allow(w)) => w,
        Ok(GateOutcome::RequireApproval) => {
            panic!("FAIL — dispatch_gate returned RequireApproval (unexpected for 'lend' verb)")
        }
        Err(e) => {
            panic!("FAIL — dispatch_gate returned error: {e:?}")
        }
    };

    // Build the DefiContractPin for the testnet Blend v2 pool.
    let pin = DefiContractPin::new(
        "blend",
        "v2",
        "default",
        TESTNET_CHAIN_ID,
        BLEND_V2_TESTNET_POOL,
        BLEND_V2_POOL_WASM_HASH_TESTNET,
        "blend-contracts-v2",
    );

    let primary_rpc = testnet_rpc();

    // The pre-submit sequence of the TRANSACTION SOURCE — the signer's
    // G-account, the account whose sequence the submit consumes and the key
    // `submit_signed_invoke` records into the hook (the smart-account
    // C-address holds no sequence). Captured independently of the adapter's
    // own internal fetch, so the assertion below verifies the EXACT consumed
    // sequence the spy observed (pre-submit sequence + 1), not merely that
    // *some* call happened.
    let pre_submit_sequence = fetch_account(&primary_rpc, &signer_g, &[])
        .await
        .expect("fetch pre-submit sequence")
        .sequence_number;

    let sequence_floor_spy = SequenceFloorSpy::default();

    // Build DefiAdapterCtx with full submit context.
    let mut ctx = DefiAdapterCtx::new_with_submit_ctx(
        "default",
        &pin,
        &primary_rpc,
        Some(signer.as_ref()),
        Some(TESTNET_PASSPHRASE),
        Some(TESTNET_CHAIN_ID),
        None, // single-RPC for testnet acceptance
        Some(Duration::from_secs(120)),
    );
    // DefiAdapterCtx -> SubmitInvokeArgs::sequence_floor threading:
    // stand in for the MCP server's process-local SequenceFloorTracker.
    ctx.sequence_floor = Some(&sequence_floor_spy);

    // Build LendArgs: supply SUPPLY_AMOUNT of the reserve asset from wallet_c.
    let lend_args = LendArgs {
        pool_address: BLEND_V2_TESTNET_POOL.to_owned(),
        from_address: wallet_c.clone(),
        requests: vec![BlendRequest::new(
            RequestType::Supply,
            supply_asset.clone(),
            SUPPLY_AMOUNT,
        )],
        override_oracle_staleness: false,
    };

    // Wire audit emission exactly as the MCP `stellar_blend_lend` handler does,
    // so the confirmed submit records its value_action_submitted row.  The legs
    // are built from the SAME requests placed into `lend_args` (single-derivation
    // invariant).  The writer uses a fixed test key; a real deployment supplies
    // the profile's audit chain-root key.
    let audit_dir = std::env::temp_dir().join(format!("blend-audit-{}", now_secs()));
    std::fs::create_dir_all(&audit_dir).expect("create audit dir");
    let audit_log_path = audit_dir.join("audit.jsonl");
    let audit_writer = std::sync::Arc::new(std::sync::Mutex::new(
        stellar_agent_core::audit_log::AuditWriter::open(
            audit_log_path.clone(),
            Some(Zeroizing::new([0x11u8; 32])),
        )
        .expect("open audit writer"),
    ));
    let audit_legs: Vec<stellar_agent_core::audit_log::ValueLegRecord> =
        stellar_agent_blend::value::blend_value_legs(&lend_args.requests, &lend_args.pool_address)
            .iter()
            .map(Into::into)
            .collect();
    ctx.audit_writer = Some(std::sync::Arc::clone(&audit_writer));
    ctx.audit_legs = Some(&audit_legs);
    ctx.audit_tool = Some("stellar_blend_lend");

    // Execute the supply.
    // NOTE: `witness` is consumed (moved) by `submit`; cannot retry.
    // submit includes its own internal retry for transient RPC issues.
    let adapter = BlendLendAdapter::new();
    let submit_result = adapter.submit(&lend_args, &ctx, witness).await;

    match submit_result {
        Ok(()) => {
            eprintln!(
                "\nVERDICT: auth-entry sub-invocation handling VALIDATED for Blend\n\
                 BlendLendAdapter::submit SUCCEEDED on-chain for wallet {}\n\
                 supply_asset={} amount={}\n\
                 The auth-entry sub-invocation handling is confirmed correct.",
                redact_strkey(&wallet_c),
                redact_strkey(&supply_asset),
                SUPPLY_AMOUNT,
            );

            // #21 — the confirmed on-chain supply must have recorded a
            // value_action_submitted row for stellar_blend_lend.
            let audit_rows: Vec<serde_json::Value> = std::io::BufRead::lines(
                std::io::BufReader::new(
                    std::fs::File::open(&audit_log_path).expect("audit log after submit"),
                ),
            )
            .map(|line| serde_json::from_str(&line.expect("audit line")).expect("audit JSON row"))
            .collect();
            assert!(
                audit_rows.iter().any(|row| {
                    row["kind"] == "value_action_submitted" && row["tool"] == "stellar_blend_lend"
                }),
                "confirmed Blend supply must record a value_action_submitted row: {audit_rows:?}"
            );

            // The confirmed on-chain supply must have recorded the
            // consumed sequence into the threaded SequenceFloorHook, exactly
            // as the classic commit verbs record into their tracker on
            // confirmed submit (source_sequence + 1).
            let recorded = sequence_floor_spy.recorded.lock().expect("lock").clone();
            assert_eq!(
                recorded,
                vec![(signer_g.clone(), pre_submit_sequence + 1)],
                "confirmed Blend supply must record exactly one \
                 (source_account, consumed_sequence) pair into the sequence \
                 floor hook, matching pre_submit_sequence + 1: {recorded:?}"
            );
        }
        Err(e) => {
            // Full error is printed — this is the critical diagnostic output.
            let error_str = format!("{e:?}");
            // Check for the specific auth/check_auth error patterns that would
            // indicate the signed auth entry is wrong.
            let is_auth_failure = error_str.contains("__check_auth")
                // SaError::RuleIdMismatch Display: "context rule-ID mismatch: expected len N, observed len M"
                || error_str.contains("RuleIdMismatch")
                || error_str.contains("context rule-ID mismatch")
                || error_str.contains("observed len 0")
                || error_str.contains("AuthEntryConstructionFailed")
                // SaError ContextRuleIds variants
                || error_str.contains("context-rule")
                || error_str.contains("ContextRuleIdsLengthMismatch")
                || error_str.contains("UnvalidatedContext");

            if is_auth_failure {
                panic!(
                    "\nVERDICT: FAILED (auth/check_auth error)\n\
                     the signed auth entry is WRONG or INCOMPLETE for Blend.\n\
                     BlendLendAdapter::submit FAILED with auth-related error:\n\
                     {e:?}\n\
                     wallet_c={}\n\
                     supply_asset={} amount={}\n\
                     This indicates the auth-entry sub-invocation construction \
                     did not produce a valid signed auth for \
                     the Blend pool's require_auth call and SAC transfer sub-invocation.",
                    redact_strkey(&wallet_c),
                    redact_strkey(&supply_asset),
                    SUPPLY_AMOUNT,
                );
            } else {
                panic!(
                    "\nVERDICT: FAILED (non-auth error)\n\
                     BlendLendAdapter::submit FAILED with non-auth error:\n\
                     {e:?}\n\
                     wallet_c={}\n\
                     supply_asset={} amount={}\n\
                     This may be an environmental issue (testnet RPC, pool state) \
                     rather than a wallet auth-entry defect. Investigate the error above.",
                    redact_strkey(&wallet_c),
                    redact_strkey(&supply_asset),
                    SUPPLY_AMOUNT,
                );
            }
        }
    }
}
