//! Testnet acceptance tests for the Soroswap `trade` (swap) adapter.
//!
//! Gated behind the `testnet-acceptance` feature flag:
//!
//! ```text
//! cargo test -p stellar-agent-dex --features testnet-acceptance \
//!   --test dex_swap_testnet_acceptance
//! ```
//!
//! Under default `cargo test` (no `--features testnet-acceptance`), this file
//! compiles but all tests are compiled-out via
//! `#[cfg(feature = "testnet-acceptance")]`.
//!
//! # Acceptance criteria covered
//!
//! - Venue allowlist check: testnet router address passes; unknown
//!   address refuses; unrecognised network refuses.
//!
//! - Token canonicalisation: bare `native` token resolves to the
//!   known-answer XLM SAC (`CDLZFC3...`) on testnet; `percent-string` path
//!   values are refused by `validate_trade_args`.
//!
//! - Typed preview: `build_swap_preview` produces a [`SwapPreview`]
//!   with all addresses first-5-last-5 redacted, absolute `amount_out_min`
//!   carried through, and deadline present.
//!
//! - Pin-verify: the Soroswap testnet router WASM-hash matches the
//!   pinned value; mismatched all-zeros hash refuses.
//!
//! - On-chain quote: `fetch_quote` returns a non-empty amounts vector
//!   for the testnet XLM→USDC swap path; `reverify_slippage` passes when
//!   `amount_out_min` is zero; `reverify_slippage` refuses when
//!   `amount_out_min` exceeds the on-chain quote.  RPC failure is a HARD test
//!   failure (no fail-soft).
//!
//! # RPC transient failures
//!
//! Tests use the shared acceptance retry helper before failing. If persistently
//! unreachable, the test notes this and the authoritative green run is the
//! post-push `workflow_dispatch` CI.

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

use stellar_agent_dex::{
    abi::TradeArgs,
    adapter::validate_trade_args_pub,
    pins::{
        SOROSWAP_ROUTER_ADDRESS_TESTNET, SOROSWAP_ROUTER_WASM_HASH_TESTNET,
        verify_soroswap_router_wasm,
    },
    preview::build_swap_preview,
    quote::{QuoteError, fetch_quote, reverify_slippage},
    sac::{SacError, canonicalise_path, canonicalise_token},
    venue::{VenueError, check_venue_allowed},
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
/// Test-only funding helper that moves XLM SAC balance into the smart-account
/// C-address before the swap submit.
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

/// Known-answer XLM SAC on testnet.
///
/// Verified at `stellar-agent-dex/src/sac.rs` KAT test; also listed in
/// `soroswap-core/public/tokens.json` (testnet `XLM`).
const XLM_SAC_TESTNET: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

/// USDC on testnet (Soroswap-listed token with an XLM/USDC pool).
///
/// Source: `soroswap-core/public/tokens.json` (testnet `USDC`).
const USDC_TESTNET: &str = "CB3TLW74NBIOT3BUWOZ3TUM6RFDF6A4GVIRUQRQZABG5KPOUL4JJOV2F";

/// A fake wallet address for preview construction.
///
/// Not actually signing anything in these gate-only tests.
const FAKE_WALLET_ADDR: &str = "CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns a fresh `StellarRpcClient` for the testnet RPC.
fn testnet_rpc() -> StellarRpcClient {
    StellarRpcClient::new(TESTNET_RPC_URL).expect("testnet RPC URL must be valid")
}

/// Returns the current UNIX timestamp in seconds.
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
// Acceptance — Venue allowlist
// ─────────────────────────────────────────────────────────────────────────────

/// **Acceptance** — Venue allowlist: pass for known router, refuse for unknown.
///
/// Verifies:
/// 1. The testnet Soroswap router address passes the allowlist check.
/// 2. An unknown router address is refused with `VenueError::NotAllowlisted`.
/// 3. An unrecognised network is refused with `VenueError::UnrecognisedNetwork`.
/// 4. The error `Display` does not leak the full router address.
#[test]
fn acceptance_venue_allowlist() {
    // ── Step 1: known router passes ──────────────────────────────────────────
    let result = check_venue_allowed(SOROSWAP_ROUTER_ADDRESS_TESTNET, TESTNET_CHAIN_ID);
    assert!(
        result.is_ok(),
        "Acceptance FAIL — testnet router must pass venue allowlist: {result:?}"
    );

    // ── Step 2: unknown address refuses ──────────────────────────────────────
    let unknown = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
    let result = check_venue_allowed(unknown, TESTNET_CHAIN_ID);
    assert!(
        matches!(result, Err(VenueError::NotAllowlisted { .. })),
        "Acceptance FAIL — unknown router must be refused with NotAllowlisted: {result:?}"
    );

    // ── Step 3: unrecognised network refuses ──────────────────────────────────
    let result = check_venue_allowed(SOROSWAP_ROUTER_ADDRESS_TESTNET, "stellar:futurenet");
    assert!(
        matches!(result, Err(VenueError::UnrecognisedNetwork { .. })),
        "Acceptance FAIL — unrecognised network must return UnrecognisedNetwork: {result:?}"
    );

    // ── Step 4: error Display must not leak full address ─────────────────────
    let err = VenueError::NotAllowlisted {
        router_redacted: "CCJUD...7BRD".to_owned(),
        network: TESTNET_CHAIN_ID.to_owned(),
    };
    let display = err.to_string();
    assert!(
        !display.contains(SOROSWAP_ROUTER_ADDRESS_TESTNET),
        "Acceptance FAIL — VenueError Display must not leak full address; got: {display}"
    );

    eprintln!("Acceptance PASS — venue allowlist checks all pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Acceptance — Token canonicalisation
// ─────────────────────────────────────────────────────────────────────────────

/// **Acceptance** — Token canonicalisation to SAC.
///
/// Verifies:
/// 1. `native` resolves to the known-answer XLM SAC on testnet.
/// 2. `XLM:native` is refused (`native` is not a valid G-strkey issuer).
/// 3. An already-canonical C-strkey passes through unchanged.
/// 4. `canonicalise_path` on a two-element path returns C-strkeys.
/// 5. A percent-format `50%` value returns `Err(SacError::UnrecognisedFormat)`.
#[test]
fn acceptance_token_canonicalisation() {
    // ── Step 1: `native` → XLM SAC KAT ──────────────────────────────────────
    let result = canonicalise_token("native", TESTNET_PASSPHRASE);
    assert!(
        result.is_ok(),
        "Acceptance FAIL — 'native' must canonicalise: {result:?}"
    );
    assert_eq!(
        result.unwrap(),
        XLM_SAC_TESTNET,
        "Acceptance FAIL — 'native' must yield the known-answer XLM SAC"
    );

    // ── Step 2: `XLM:native` is NOT a valid token format ────────────────────
    // `XLM:native` tries to parse `native` as a G-strkey issuer, which fails.
    // The canonical form for native XLM is just `"native"` (the issuer-free form).
    // Classic asset format is `"CODE:G..."` where the issuer is a G-strkey.
    let result = canonicalise_token("XLM:native", TESTNET_PASSPHRASE);
    assert!(
        result.is_err(),
        "Acceptance — 'XLM:native' must fail (native is not a valid G-strkey issuer); got Ok"
    );

    // ── Step 3: already-canonical C-strkey passes through ────────────────────
    let result = canonicalise_token(XLM_SAC_TESTNET, TESTNET_PASSPHRASE);
    assert!(
        result.is_ok(),
        "Acceptance FAIL — already-canonical C-strkey must pass through: {result:?}"
    );
    assert_eq!(
        result.unwrap(),
        XLM_SAC_TESTNET,
        "Acceptance FAIL — canonical C-strkey must be returned unchanged"
    );

    // ── Step 4: canonicalise_path on two-element path ─────────────────────────
    let path = vec![XLM_SAC_TESTNET.to_owned(), USDC_TESTNET.to_owned()];
    let result = canonicalise_path(&path, TESTNET_PASSPHRASE);
    assert!(
        result.is_ok(),
        "Acceptance FAIL — two-element canonical path must succeed: {result:?}"
    );
    let canonical = result.unwrap();
    assert_eq!(canonical.len(), 2, "canonical path must have 2 elements");
    assert_eq!(canonical[0], XLM_SAC_TESTNET);

    // ── Step 5: percent-format refuses ───────────────────────────────────────
    let result = canonicalise_token("50%", TESTNET_PASSPHRASE);
    assert!(
        matches!(result, Err(SacError::UnrecognisedFormat)),
        "Acceptance FAIL — '50%' must return UnrecognisedFormat: {result:?}"
    );

    eprintln!("Acceptance PASS — token canonicalisation all pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Acceptance — Typed preview
// ─────────────────────────────────────────────────────────────────────────────

/// **Acceptance** — Typed preview surface.
///
/// Verifies:
/// 1. `build_swap_preview` produces a [`SwapPreview`] with non-empty fields.
/// 2. `amount_in` and `amount_out_min` carry through unchanged (no rounding,
///    no percent conversion).
/// 3. All addresses are first-5-last-5 redacted (full address not in preview).
/// 4. `deadline` is set (non-zero).
/// 5. `DefiPreview.protocol` == `"soroswap"`, `verb` == `"trade"`.
#[test]
fn acceptance_typed_preview() {
    let resolved_deadline = now_secs() + 300;

    let args = TradeArgs {
        from_address: FAKE_WALLET_ADDR.to_owned(),
        amount_in: 10_000_000,     // 1 XLM (7 decimals)
        amount_out_min: 9_800_000, // 0.98 USDC absolute floor
        path: vec![XLM_SAC_TESTNET.to_owned(), USDC_TESTNET.to_owned()],
        deadline: Some(resolved_deadline),
    };

    let (swap_preview, defi_preview) = build_swap_preview(
        &args,
        SOROSWAP_ROUTER_ADDRESS_TESTNET,
        &args.path,
        resolved_deadline,
        TESTNET_CHAIN_ID,
        None,
    );

    // ── Step 1: fields are non-empty ─────────────────────────────────────────
    assert!(
        !swap_preview.router_address_redacted.is_empty(),
        "Acceptance FAIL — router_address_redacted must not be empty"
    );
    assert!(
        !swap_preview.from_address_redacted.is_empty(),
        "Acceptance FAIL — from_address_redacted must not be empty"
    );

    // ── Step 2: amounts carry through unchanged ───────────────────────────────
    assert_eq!(
        swap_preview.amount_in, args.amount_in,
        "Acceptance FAIL — amount_in must carry through unchanged"
    );
    assert_eq!(
        swap_preview.amount_out_min, args.amount_out_min,
        "Acceptance FAIL — amount_out_min must carry through unchanged (absolute, not percent)"
    );

    // ── Step 3: addresses are redacted ───────────────────────────────────────
    assert!(
        !swap_preview
            .router_address_redacted
            .contains(SOROSWAP_ROUTER_ADDRESS_TESTNET),
        "Acceptance FAIL — router address must be redacted in preview"
    );
    assert!(
        !swap_preview
            .from_address_redacted
            .contains(FAKE_WALLET_ADDR),
        "Acceptance FAIL — from address must be redacted in preview"
    );
    for redacted in &swap_preview.path_redacted {
        assert!(
            !redacted.contains(XLM_SAC_TESTNET),
            "Acceptance FAIL — path address must be redacted: got {redacted}"
        );
    }
    assert!(
        !defi_preview
            .contract_address_redacted
            .contains(SOROSWAP_ROUTER_ADDRESS_TESTNET),
        "Acceptance FAIL — router address must be redacted in DefiPreview"
    );

    // ── Step 4: deadline is set ───────────────────────────────────────────────
    assert!(
        swap_preview.deadline > 0,
        "Acceptance FAIL — deadline must be non-zero"
    );
    assert_eq!(
        swap_preview.deadline, resolved_deadline,
        "Acceptance FAIL — deadline must match resolved_deadline"
    );

    // ── Step 5: DefiPreview protocol and verb ────────────────────────────────
    assert_eq!(
        defi_preview.protocol, "soroswap",
        "Acceptance FAIL — DefiPreview.protocol must be 'soroswap'"
    );
    assert_eq!(
        defi_preview.verb, "trade",
        "Acceptance FAIL — DefiPreview.verb must be 'trade'"
    );

    eprintln!(
        "Acceptance PASS — typed preview: amount_in={}, amount_out_min={}, deadline={}",
        swap_preview.amount_in, swap_preview.amount_out_min, swap_preview.deadline,
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Acceptance — Negative amount_out_min refused at args level
// ─────────────────────────────────────────────────────────────────────────────

/// **Acceptance** — Negative `amount_out_min` refused by `validate_trade_args`.
///
/// `TradeArgs.amount_out_min` is a required `i128` field.  A percent string (e.g.
/// `"50%"`) is structurally unrepresentable — it fails JSON deserialization before
/// reaching this layer.  This acceptance test verifies the validation path for
/// `amount_out_min < 0` by calling `validate_trade_args` directly and asserting
/// the error kind.
///
/// No percent-string is accepted; the `i128` type enforces the structural
/// refusal at the parse boundary.
#[test]
fn acceptance_negative_amount_out_min_refused() {
    let args = TradeArgs {
        from_address: FAKE_WALLET_ADDR.to_owned(),
        amount_in: 10_000_000,
        amount_out_min: -1, // negative is invalid; structural proxy for percent-string refusal
        path: vec![XLM_SAC_TESTNET.to_owned(), USDC_TESTNET.to_owned()],
        deadline: None,
    };

    let result = validate_trade_args_pub(&args);
    assert!(
        result.is_err(),
        "Acceptance FAIL — validate_trade_args must refuse amount_out_min=-1; got Ok"
    );

    eprintln!(
        "Acceptance PASS — validate_trade_args refused amount_out_min=-1 with {:?}",
        result.unwrap_err()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Acceptance — Pin-verify
// ─────────────────────────────────────────────────────────────────────────────

/// **Acceptance** — Router WASM-hash pin-verify against testnet.
///
/// Verifies:
/// 1. The testnet Soroswap router WASM hash matches the pinned value
///    `4b95bbf9caec2c6e00c786f53c5f392c2fcdb8435ac0a862ab5e0645eb65824c`.
/// 2. The pubnet TBD sentinel (all-zeros) refuses immediately without any
///    RPC call (`PinNotSet` variant).
#[tokio::test]
#[ignore = "live testnet acceptance; run in the testnet-acceptance CI job via -- --ignored"]
async fn acceptance_pin_verify_testnet_router() {
    let rpc = testnet_rpc();

    // ── Step 1: testnet router WASM hash passes ───────────────────────────────
    // Pass None as secondary RPC (honest single-RPC; same client for both would
    // defeat the divergence check).
    let result = retry_rpc!(verify_soroswap_router_wasm(
        SOROSWAP_ROUTER_ADDRESS_TESTNET,
        TESTNET_CHAIN_ID,
        &rpc,
        None, // honest single-RPC; secondary is None when only one endpoint is configured
    ));

    match result {
        Ok(()) => {
            // Pin-verify passed. Good.
        }
        Err(e) => {
            panic!("Acceptance FAIL — testnet router WASM pin-verify failed: {e}");
        }
    }

    eprintln!(
        "Acceptance PASS — testnet router WASM hash matches pinned value {:02x}{:02x}...{:02x}{:02x}",
        SOROSWAP_ROUTER_WASM_HASH_TESTNET[0],
        SOROSWAP_ROUTER_WASM_HASH_TESTNET[1],
        SOROSWAP_ROUTER_WASM_HASH_TESTNET[30],
        SOROSWAP_ROUTER_WASM_HASH_TESTNET[31],
    );
}

/// **Acceptance** — Pubnet TBD sentinel refuses without RPC.
///
/// The all-zeros WASM hash for pubnet is a `TBD` sentinel that causes
/// `verify_soroswap_router_wasm` to refuse immediately (before any RPC call)
/// with `DexPinError::PinNotSet`.
#[tokio::test]
async fn acceptance_pubnet_tbd_sentinel_refuses() {
    use stellar_agent_dex::pins::{
        DexPinError, SOROSWAP_ROUTER_ADDRESS_PUBNET, verify_soroswap_router_wasm,
    };

    // The pubnet WASM-hash sentinel makes verification refuse with PinNotSet
    // before any RPC call (the client below is never contacted).
    let rpc = testnet_rpc();
    let result =
        verify_soroswap_router_wasm(SOROSWAP_ROUTER_ADDRESS_PUBNET, "stellar:pubnet", &rpc, None)
            .await;
    assert!(
        matches!(result, Err(DexPinError::PinNotSet)),
        "Acceptance FAIL — pubnet must refuse with PinNotSet; got {result:?}"
    );

    eprintln!("Acceptance PASS — pubnet TBD sentinel refuses with PinNotSet before any RPC call");
}

// ─────────────────────────────────────────────────────────────────────────────
// Acceptance — On-chain quote + slippage reverify
// ─────────────────────────────────────────────────────────────────────────────

/// **Acceptance** — On-chain `router_get_amounts_out` quote + slippage reverify.
///
/// Verifies:
/// 1. `fetch_quote` returns a non-empty `amounts` vector for the testnet
///    XLM→USDC swap path.
/// 2. `QuoteResult::expected_out()` is `Some(N)` with `N > 0`.
/// 3. `reverify_slippage` passes when `amount_out_min = 0` (accept any output).
/// 4. `reverify_slippage` refuses when `amount_out_min` exceeds the on-chain
///    quote, returning `QuoteError::SlippageExceeded`.
///
/// # RPC failures
///
/// RPC failure is a HARD test failure — the `testnet-acceptance` feature flag
/// asserts live testnet connectivity.  An environmental RPC gap is a CI
/// configuration issue, not a reason to silently PASS.
#[tokio::test]
#[ignore = "live testnet acceptance; run in the testnet-acceptance CI job via -- --ignored"]
async fn acceptance_onchain_quote_and_reverify() {
    // XLM → USDC path on testnet.
    let path = vec![XLM_SAC_TESTNET.to_owned(), USDC_TESTNET.to_owned()];
    let amount_in: i128 = 10_000_000; // 1 XLM (7 decimals)

    // ── Step 1: fetch on-chain quote ──────────────────────────────────────────
    // Hard failure on RPC error: testnet-acceptance asserts live connectivity.
    let quote_result = retry_rpc!(fetch_quote(
        SOROSWAP_ROUTER_ADDRESS_TESTNET,
        amount_in,
        &path,
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
    ));

    let quote = quote_result.unwrap_or_else(|e| {
        panic!(
            "Acceptance FAIL — testnet RPC unavailable for quote fetch (hard failure; \
             testnet-acceptance requires live connectivity): {e:?}"
        )
    });

    // ── Step 2: expected_out is Some and positive ─────────────────────────────
    let expected_out = quote.expected_out();
    assert!(
        expected_out.is_some(),
        "Acceptance FAIL — expected_out must be Some after quote fetch"
    );
    let out = expected_out.unwrap();
    assert!(
        out > 0,
        "Acceptance FAIL — on-chain expected_out must be positive; got {out}"
    );
    eprintln!("Acceptance — on-chain quote: amount_in={amount_in}, expected_out={out}");

    // ── Step 3: reverify passes with amount_out_min = 0 ──────────────────────
    let reverify_pass = retry_rpc!(reverify_slippage(
        SOROSWAP_ROUTER_ADDRESS_TESTNET,
        amount_in,
        0, // accept any output
        &path,
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
    ));

    match reverify_pass {
        Ok(qr) => {
            eprintln!(
                "Acceptance — reverify passed with amount_out_min=0: expected_out={:?}",
                qr.expected_out()
            );
        }
        Err(e) => {
            panic!("Acceptance FAIL — reverify_slippage with amount_out_min=0 must pass: {e:?}");
        }
    }

    // ── Step 4: reverify refuses when amount_out_min > expected_out ───────────
    let impossible_min = out * 2; // double the expected output — impossible
    let reverify_fail = retry_rpc!(reverify_slippage(
        SOROSWAP_ROUTER_ADDRESS_TESTNET,
        amount_in,
        impossible_min,
        &path,
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
    ));

    match reverify_fail {
        Err(QuoteError::SlippageExceeded { .. }) => {
            // Correct: slippage exceeded
        }
        other => {
            panic!(
                "Acceptance FAIL — reverify_slippage with impossible amount_out_min must \
                 return SlippageExceeded; got: {other:?}"
            );
        }
    }

    eprintln!(
        "Acceptance PASS — on-chain quote={out}, reverify(0)=pass, \
         reverify({impossible_min})=SlippageExceeded"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Acceptance — Real on-chain swap submit-and-confirm
// ─────────────────────────────────────────────────────────────────────────────

/// **Acceptance** — Real on-chain ROUTER-DIRECT swap submit-and-confirm +
/// multi-auth-entry guard verification.
///
/// Verifies:
/// 1. A fresh ed25519 signer + fresh smart-account (C-address) can be deployed
///    via the Friendbot-funded deployer pattern.
/// 2. The smart-account C-address can be funded with XLM SAC balance via the
///    XLM SAC `transfer(from_g, to_c, amount)` 8-step Soroban flow.
/// 3. `DexSwapAdapter::submit` executes a REAL on-chain ROUTER-DIRECT swap
///    (XLM → USDC) successfully (transaction confirmed on-chain).
/// 4. The multi-auth-entry guard observed EXACTLY 1 wallet-credentialled root
///    auth entry (count == 1).
///
/// # RPC failures
///
/// All steps are HARD failures — no fail-soft silent PASS.  Testnet RPC
/// unavailability is a CI configuration issue, not a test skip condition.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live testnet acceptance; run in the testnet-acceptance CI job via -- --ignored"]
async fn acceptance_submit_and_confirm() {
    use stellar_agent_defi::{
        adapter::{DefiAdapter, DefiAdapterCtx},
        dispatch::{GateOutcome, dispatch_gate},
        pins::DefiContractPin,
    };
    use stellar_agent_dex::{
        abi::TradeArgs, adapter::DexSwapAdapter, pins::SOROSWAP_ROUTER_WASM_HASH_TESTNET,
        quote::fetch_quote,
    };

    // ── Constants ─────────────────────────────────────────────────────────────
    const FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
    /// Amount to fund the smart-account with: 10 XLM in stroops (7 decimals).
    const FUND_AMOUNT: i128 = 100_000_000; // 10 XLM
    /// Amount to swap: 1 XLM.
    const SWAP_AMOUNT_IN: i128 = 10_000_000; // 1 XLM

    let deployed = deploy_funded_smart_account(
        "Acceptance —",
        "testnet-dex-acceptance-generated",
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
        FRIENDBOT_URL,
        make_testnet_signer,
        deploy_testnet_smart_account,
    )
    .await
    .unwrap_or_else(|e| panic!("Acceptance FAIL — smart-account deployment failed: {e:?}"));
    let wallet_c = deployed.wallet_c;
    let signer = deployed.signer;

    // ── Step 3: Fund smart-account C-address with XLM SAC balance ────────────
    // A smart-account C-address cannot receive classic XLM payments.
    // Must call XLM SAC `transfer(from_g, to_c, amount)` via 8-step Soroban flow:
    //   1. Build InvokeContractArgs
    //   2. simulateTransaction → get auth entry nonce + latest_ledger
    //   3. Set signature_expiration_ledger on auth entry
    //   4. Sign auth entry via sign_soroban_auth_entry (single call site)
    //   5. Re-simulate with signed auth entry (MANDATORY footprint refresh)
    //   6. Build final envelope with min_resource_fee from re-simulate
    //   7. Submit via sendTransaction
    //   8. Confirm on-chain

    let fund_result = fund_sac_balance(
        "Acceptance —",
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
    .unwrap_or_else(|e| panic!("Acceptance FAIL — SAC transfer submit failed: {e:?}"));

    eprintln!(
        "Acceptance — SAC transfer confirmed on-chain: ledger={}",
        fund_result.ledger
    );

    // ── Step 4: Fetch live quote for 1 XLM → USDC ───────────────────────────
    eprintln!("Acceptance — Step 4: fetching live on-chain quote");
    let swap_path = vec![XLM_SAC_TESTNET.to_owned(), USDC_TESTNET.to_owned()];

    let quote_result = retry_rpc!(fetch_quote(
        SOROSWAP_ROUTER_ADDRESS_TESTNET,
        SWAP_AMOUNT_IN,
        &swap_path,
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
    ))
    .unwrap_or_else(|e| {
        panic!(
            "Acceptance FAIL — fetch_quote failed (hard failure; \
             testnet-acceptance requires live connectivity): {e:?}"
        )
    });

    let expected_out = quote_result
        .expected_out()
        .expect("Acceptance FAIL — expected_out must be Some after quote fetch");
    assert!(
        expected_out > 0,
        "Acceptance FAIL — expected_out must be positive; got {expected_out}"
    );

    // amount_out_min = 95% of expected_out (safe floor below normal testnet movement).
    let amount_out_min = expected_out * 95 / 100;
    eprintln!(
        "Acceptance — quote: amount_in={SWAP_AMOUNT_IN}, expected_out={expected_out}, \
         amount_out_min={amount_out_min}"
    );

    // ── Step 5: Execute the real on-chain swap via DexSwapAdapter::submit ───
    eprintln!("Acceptance — Step 5: executing real on-chain swap via DexSwapAdapter::submit");

    // Build the dispatch gate witness for "trade" verb.
    let request_id = format!("dex-swap-acceptance-{}", now_secs());
    let witness = match dispatch_gate("trade", request_id.clone()) {
        Ok(GateOutcome::Allow(w)) => w,
        Ok(GateOutcome::RequireApproval) => {
            panic!("Acceptance FAIL — dispatch_gate returned RequireApproval (unexpected)")
        }
        Err(e) => {
            panic!("Acceptance FAIL — dispatch_gate returned error: {e:?}")
        }
    };

    // Build the DefiContractPin for the testnet Soroswap router.
    let pin = DefiContractPin::new(
        "soroswap",
        "router-direct",
        "default",
        TESTNET_CHAIN_ID,
        SOROSWAP_ROUTER_ADDRESS_TESTNET,
        SOROSWAP_ROUTER_WASM_HASH_TESTNET,
        "soroswap-core",
    );

    let primary_rpc = testnet_rpc();

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

    // Build TradeArgs.
    let trade_args = TradeArgs {
        from_address: wallet_c.clone(),
        amount_in: SWAP_AMOUNT_IN,
        amount_out_min,
        path: swap_path,
        deadline: None, // adapter defaults to now + 300s
    };

    // Wire audit emission exactly as the MCP `stellar_dex_trade` handler does,
    // so the confirmed swap records its value_action_submitted row.  The leg is
    // built from the SAME amount/path/router the trade uses (single-derivation
    // invariant); the writer uses a fixed test key.
    let audit_dir = std::env::temp_dir().join(format!("dex-audit-{}", now_secs()));
    std::fs::create_dir_all(&audit_dir).expect("create audit dir");
    let audit_log_path = audit_dir.join("audit.jsonl");
    let audit_writer = std::sync::Arc::new(std::sync::Mutex::new(
        stellar_agent_core::audit_log::AuditWriter::open(
            audit_log_path.clone(),
            Some(Zeroizing::new([0x11u8; 32])),
        )
        .expect("open audit writer"),
    ));
    let audit_legs = vec![stellar_agent_core::audit_log::ValueLegRecord::from(
        &stellar_agent_dex::value::dex_trade_value_leg(
            trade_args.amount_in,
            &trade_args.path,
            SOROSWAP_ROUTER_ADDRESS_TESTNET,
        ),
    )];
    ctx.audit_writer = Some(std::sync::Arc::clone(&audit_writer));
    ctx.audit_legs = Some(&audit_legs);
    ctx.audit_tool = Some("stellar_dex_trade");

    // Execute the swap.
    // NOTE: `witness` is consumed (moved) by `submit`; cannot retry.
    // submit includes its own internal retry for transient RPC issues.
    let adapter = DexSwapAdapter::new();
    let submit_result = adapter.submit(&trade_args, &ctx, witness).await;

    submit_result.unwrap_or_else(|e| {
        panic!(
            "Acceptance FAIL — DexSwapAdapter::submit failed: {e:?}\n\
             wallet_c={}\n\
             This indicates the swap was rejected on-chain or a guard failed.",
            redact_strkey(&wallet_c)
        )
    });

    eprintln!(
        "Acceptance PASS — real on-chain swap SUCCEEDED for wallet {}",
        redact_strkey(&wallet_c)
    );

    // #21 — the confirmed on-chain swap must have recorded a
    // value_action_submitted row for stellar_dex_trade.
    let audit_rows: Vec<serde_json::Value> = std::io::BufRead::lines(std::io::BufReader::new(
        std::fs::File::open(&audit_log_path).expect("audit log after submit"),
    ))
    .map(|line| serde_json::from_str(&line.expect("audit line")).expect("audit JSON row"))
    .collect();
    assert!(
        audit_rows.iter().any(|row| {
            row["kind"] == "value_action_submitted" && row["tool"] == "stellar_dex_trade"
        }),
        "confirmed DEX swap must record a value_action_submitted row: {audit_rows:?}"
    );

    // ── Step 6: Assert the multi-auth-entry guard observed count == 1 ─
    // DexSwapAdapter::submit integrates count_wallet_auth_entries as step 8 of
    // the ordered trust gate.  If submit() returned Ok(()), the guard passed,
    // meaning count == 1.  We verify this explicitly here by re-running the guard
    // and asserting the count directly via a ROUTER-DIRECT simulate.
    //
    // ROUTER-DIRECT invocation produces exactly 1 wallet-credentialled root auth
    // context.  The router calls `to.require_auth()` in
    // soroswap-core router/src/lib.rs; the SAC `transfer(from=wallet)` is a
    // sub-invocation covered by that single root entry.
    eprintln!("Acceptance — Step 6: verifying multi-auth-entry guard (count == 1)");

    use stellar_agent_dex::auth_guard::count_wallet_auth_entries;
    use stellar_agent_dex::scval::encode_swap_args;

    // Deadline must be in the future for the re-verify simulate.
    let verify_deadline = now_secs() + 300;
    let scval_args = encode_swap_args(
        SWAP_AMOUNT_IN,
        amount_out_min,
        &[XLM_SAC_TESTNET.to_owned(), USDC_TESTNET.to_owned()],
        &wallet_c,
        verify_deadline,
    )
    .expect("encode_swap_args must succeed for guard re-verify");

    let guard_count = retry_rpc!(count_wallet_auth_entries(
        &wallet_c,
        SOROSWAP_ROUTER_ADDRESS_TESTNET,
        &scval_args,
        TESTNET_RPC_URL,
    ))
    .unwrap_or_else(|e| {
        panic!(
            "Acceptance FAIL — multi-auth-entry guard re-verify failed: {e:?}\n\
             expected count == 1 for a ROUTER-DIRECT swap; the router calls \
             to.require_auth() on the wallet"
        )
    });

    assert_eq!(
        guard_count, 1,
        "Acceptance FAIL — multi-auth-entry guard count must be 1 for \
         ROUTER-DIRECT; got {guard_count}"
    );

    eprintln!(
        "Acceptance PASS — ROUTER-DIRECT produces exactly 1 auth context; \
         guard count == {guard_count} for wallet {}",
        redact_strkey(&wallet_c)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Acceptance — Deadline constants (structural)
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies the deadline default and maximum constants.
///
/// This is a structural test that does not require network access.  The ordered
/// trust gate sequencing (`check_venue_allowed` → `verify_soroswap_router_wasm`
/// → `reverify_slippage`) is enforced by `?`-early-return in
/// `DexSwapAdapter::submit` and exercised end-to-end by the on-chain submit
/// acceptance test; it is not a constant and is not asserted here.
#[test]
fn acceptance_deadline_default_and_max_constants() {
    use stellar_agent_dex::abi::{DEFAULT_DEADLINE_OFFSET_SECS, MAX_DEADLINE_OFFSET_SECS};

    // Deadline defaults.
    assert_eq!(
        DEFAULT_DEADLINE_OFFSET_SECS, 300,
        "DEFAULT_DEADLINE_OFFSET_SECS must be 300s"
    );
    assert_eq!(
        MAX_DEADLINE_OFFSET_SECS, 3600,
        "MAX_DEADLINE_OFFSET_SECS must be 3600s (1h)"
    );

    eprintln!("Acceptance — deadline constants verified");
}
