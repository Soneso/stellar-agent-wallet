//! `stellar-agent claim` subcommand — claimable-balance claim spine.
//!
//! Claims a Stellar `ClaimClaimableBalance` operation for a balance the agent
//! already holds the id of. Supports the same three execution stages as `pay`:
//!
//! 1. **Build** (`--build-only`) — fetch the entry, render a typed preview, run
//!    the claim guards, construct the transaction envelope, and emit unsigned
//!    base64 XDR.
//! 2. **Sign** (`--sign-only <base64-xdr>`) — sign a previously-built envelope
//!    and emit signed base64 XDR.
//! 3. **Submit** (`--submit-only <base64-xdr>`) — submit a signed envelope and
//!    poll until confirmation.
//!
//! Default (no stage flag): runs all three stages atomically.
//!
//! # Claim guards
//!
//! Before signing, the build stage enforces the claim guards in order:
//! claimant membership (`claim.not_claimant`), predicate satisfaction
//! (`claim.predicate_not_satisfied`), non-native trustline state
//! (`claim.trustline_*`), and native-XLM fee affordability
//! (`ledger.insufficient_balance`). Claiming credits the account, so the
//! affordability check covers only the transaction fee, not the claimed amount.
//!
//! # Mainnet rejection
//!
//! `--network testnet` is the only accepted value. Mainnet is structurally
//! rejected at two layers: the CLI `TargetNetwork::Mainnet` variant returns
//! `network.mainnet_write_forbidden` before any RPC call, and
//! `submit_transaction_and_wait` rejects mainnet-looking URLs as defence in
//! depth.
//!
//! # Signer model
//!
//! Signing follows the `pay` model: `--secret-env VAR` (the shared
//! mlock-protected software signing ceremony via
//! `resolve_software_signer_from_env`) or `--sign-with-ledger` (hardware
//! signer; no seed ever in process memory). The public key derived from the
//! signer is compared against `--source` before any signing.

use std::time::Duration;

use clap::{ArgGroup, Args};
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{
    AuthError, InternalError, LedgerError, NetworkError, ValidationError, WalletError,
};

use stellar_agent_claimable::entry::{fetch_claimable_balance_entry, fetch_trustline_state};
use stellar_agent_claimable::error::ClaimError;
use stellar_agent_claimable::id::BalanceId;
use stellar_agent_claimable::preview::{
    ClaimPreview, check_trustline, require_claimant, require_predicate_satisfied,
};
use stellar_agent_network::builder::ClassicOpBuilder;
use stellar_agent_network::signing::Signer;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::signing::source::signer_from_ledger;
use stellar_agent_network::{
    BASE_RESERVE_STROOPS, ClassicFeeSelection, StellarRpcClient, SubmissionResult,
    SubmissionSignerKind, fetch_account, parse_classic_fee_choice, resolve_classic_fee_selection,
    submit_transaction_and_wait,
};

use crate::common::network::TargetNetwork;
use crate::common::render::{render_json, sanitize_for_table};
use crate::common::signer_ceremony::resolve_software_signer_from_env;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default fee per operation in stroops (100 stroops × 1 op = 100 stroops).
const DEFAULT_FEE_STROOPS: u32 = 100;

/// Default submission timeout in seconds.
const DEFAULT_TIMEOUT_SECONDS: u64 = 60;

/// Stellar testnet RPC endpoint (SDF operated).
const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";

// ─────────────────────────────────────────────────────────────────────────────
// ClaimResult — the structured success payload
// ─────────────────────────────────────────────────────────────────────────────

/// Structured payload returned in the JSON envelope on a successful claim.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClaimResult {
    /// Base64-encoded (signed or unsigned) `TransactionEnvelope` XDR.
    pub envelope_xdr: String,

    /// Transaction hash (64-character hex), present after submission.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,

    /// Ledger sequence number, present after confirmation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ledger: Option<u32>,

    /// The stage that produced this result.
    pub stage: String,

    /// Canonical 72-hex balance id being claimed.
    ///
    /// Present for the build and full-pipeline stages; absent for the
    /// sign-only and submit-only stages, which operate on an opaque envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance_id_hex72: Option<String>,
}

/// The unsigned envelope plus the metadata produced by the build stage.
#[derive(Debug, Clone)]
struct BuiltClaimEnvelope {
    envelope_xdr: String,
    balance_id_hex72: String,
    #[allow(dead_code)]
    fee_selection: ClassicFeeSelection,
}

// ─────────────────────────────────────────────────────────────────────────────
// ClaimArgs
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `claim` subcommand.
///
/// Stage flags (`--build-only`, `--sign-only`, `--submit-only`) and signer
/// flags (`--secret-env`, `--sign-with-ledger`) are each mutually exclusive via
/// an `ArgGroup`.
#[non_exhaustive]
#[derive(Debug, Args)]
#[command(
    group(ArgGroup::new("stage").args(["build_only", "sign_only", "submit_only"]).required(false)),
    group(ArgGroup::new("signer_group").args(["secret_env", "sign_with_ledger"]).required(false)),
)]
pub struct ClaimArgs {
    /// Claimable-balance id: a `B...` strkey, canonical 72-hex id, or bare
    /// 64-hex hash.
    #[arg(value_name = "BALANCE_ID")]
    pub balance_id: String,

    /// Claiming (source) account G-strkey. Also the transaction source.
    #[arg(long, value_name = "G_STRKEY")]
    pub source: String,

    /// Classic fee per operation: `<stroops>`, `auto`, or `auto:pNN`.
    #[arg(long, value_name = "STROOPS|auto[:pNN]")]
    pub fee: Option<String>,

    /// Name of the environment variable that holds the S-strkey secret key.
    /// The value of the variable is never logged.
    #[arg(long, value_name = "VAR", group = "signer_group")]
    pub secret_env: Option<String>,

    /// Sign using the connected Ledger hardware wallet.
    #[arg(long, group = "signer_group")]
    pub sign_with_ledger: bool,

    /// Ledger BIP-32 account index (default 0).
    #[arg(long, default_value_t = 0_u32, value_name = "INDEX")]
    pub account_index: u32,

    /// Build only: emit unsigned envelope XDR and exit.
    #[arg(long, group = "stage")]
    pub build_only: bool,

    /// Sign only: sign the given base64 XDR envelope and emit signed XDR.
    #[arg(long, value_name = "BASE64_XDR", group = "stage")]
    pub sign_only: Option<String>,

    /// Submit only: submit the given signed base64 XDR envelope.
    #[arg(long, value_name = "BASE64_XDR", group = "stage")]
    pub submit_only: Option<String>,

    /// Network to target. Only `testnet` is accepted.
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,

    /// Submission timeout in seconds. Default: 60.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,

    /// Override the Stellar RPC endpoint URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// run — main dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Runs the `claim` subcommand.
///
/// Dispatches to the appropriate stage (build, sign, submit, or the default
/// full pipeline) and renders the result per `args.output`.
///
/// Returns an exit code: `0` on success, `1` on any error.
///
/// # Errors
///
/// Never returns an `Err` — all errors are captured into the envelope.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &ClaimArgs) -> i32 {
    // ── Mainnet structural rejection (first layer) ────────────────────────────
    if args.network == TargetNetwork::Mainnet {
        let err = WalletError::Network(NetworkError::MainnetWriteForbidden);
        print_error(&Envelope::<()>::err(&err), args.output);
        return 1;
    }

    if args.build_only {
        run_build_only(args).await
    } else if let Some(ref xdr) = args.sign_only {
        run_sign_only(args, xdr).await
    } else if let Some(ref xdr) = args.submit_only {
        run_submit_only(args, xdr).await
    } else {
        run_full_pipeline(args).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stage implementations
// ─────────────────────────────────────────────────────────────────────────────

async fn run_build_only(args: &ClaimArgs) -> i32 {
    match build_unsigned_envelope(args).await {
        Ok(built) => {
            let result = ClaimResult {
                envelope_xdr: built.envelope_xdr,
                tx_hash: None,
                ledger: None,
                stage: "build".to_owned(),
                balance_id_hex72: Some(built.balance_id_hex72),
            };
            print_success(&Envelope::ok(result), args.output);
            0
        }
        Err(e) => {
            print_error(&claim_error_envelope(&e), args.output);
            1
        }
    }
}

async fn run_sign_only(args: &ClaimArgs, unsigned_xdr: &str) -> i32 {
    match sign_envelope(args, unsigned_xdr).await {
        Ok(signed_xdr) => {
            let result = ClaimResult {
                envelope_xdr: signed_xdr,
                tx_hash: None,
                ledger: None,
                stage: "sign".to_owned(),
                balance_id_hex72: None,
            };
            print_success(&Envelope::ok(result), args.output);
            0
        }
        Err(e) => {
            print_error(&Envelope::<()>::err(&e), args.output);
            1
        }
    }
}

async fn run_submit_only(args: &ClaimArgs, signed_xdr: &str) -> i32 {
    match submit_envelope(args, signed_xdr).await {
        Ok((signed_xdr, sub_result)) => {
            let result = ClaimResult {
                envelope_xdr: signed_xdr,
                tx_hash: Some(sub_result.tx_hash.clone()),
                ledger: Some(sub_result.ledger),
                stage: "submit".to_owned(),
                balance_id_hex72: None,
            };
            print_success(&Envelope::ok(result), args.output);
            0
        }
        Err(e) => {
            print_error(&Envelope::<()>::err(&e), args.output);
            1
        }
    }
}

async fn run_full_pipeline(args: &ClaimArgs) -> i32 {
    // 1. Build (fetch entry, preview, guards).
    let built = match build_unsigned_envelope(args).await {
        Ok(built) => built,
        Err(e) => {
            print_error(&claim_error_envelope(&e), args.output);
            return 1;
        }
    };
    let unsigned_xdr = built.envelope_xdr.clone();

    // 2. Sign.
    let signed_xdr = match sign_envelope(args, &unsigned_xdr).await {
        Ok(xdr) => xdr,
        Err(e) => {
            print_error(&Envelope::<()>::err(&e), args.output);
            return 1;
        }
    };

    // 3. Submit.
    match submit_envelope(args, &signed_xdr).await {
        Ok((xdr, sub_result)) => {
            let result = ClaimResult {
                envelope_xdr: xdr,
                tx_hash: Some(sub_result.tx_hash.clone()),
                ledger: Some(sub_result.ledger),
                stage: "build+sign+submit".to_owned(),
                balance_id_hex72: Some(built.balance_id_hex72),
            };
            print_success(&Envelope::ok(result), args.output);
            0
        }
        Err(e) => {
            print_error(&Envelope::<()>::err(&e), args.output);
            1
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Build helper
// ─────────────────────────────────────────────────────────────────────────────

/// Fetches the entry, renders a typed preview, runs the claim guards, and
/// constructs the unsigned envelope XDR.
///
/// The preview is rendered to stdout before the guards run so the operator sees
/// the balance disclosure even when a guard subsequently refuses.
async fn build_unsigned_envelope(args: &ClaimArgs) -> Result<BuiltClaimEnvelope, ClaimError> {
    let id = BalanceId::parse(&args.balance_id)?;

    // Validate the source G-strkey up front.
    stellar_strkey::ed25519::PublicKey::from_string(&args.source).map_err(|_| {
        WalletError::Validation(ValidationError::AddressInvalid {
            input: args.source.clone(),
        })
    })?;

    let client = StellarRpcClient::new(&args.rpc_url)?;

    let entry = fetch_claimable_balance_entry(&client, &id).await?;

    // Fetch the source account for the sequence number and native balance.
    // Empty trustline-request slice: the trustline guard fetch (below) is a
    // separate call keyed on the balance's own asset.
    let account_view = fetch_account(&client, &args.source, &[]).await?;

    let now_secs = current_unix_secs()?;
    let preview = ClaimPreview::build(&entry, &args.source, now_secs)?;

    // ── Render the typed preview before running the guards ────────────────────
    render_preview(&preview, args.output);

    // ── Claim guards, in order ────────────────────────────────────────────────
    require_claimant(&preview, &args.source)?;
    require_predicate_satisfied(&preview)?;
    if preview.asset_code.is_some() {
        let code = preview.asset_code.as_deref().unwrap_or_default();
        let issuer = preview.asset_issuer.as_deref().unwrap_or_default();
        let state = fetch_trustline_state(&client, &args.source, code, issuer).await?;
        check_trustline(
            &state,
            preview.asset_code.as_deref(),
            preview.asset_issuer.as_deref(),
            preview.amount_stroops,
        )?;
    }

    // ── Fee resolution + affordability ────────────────────────────────────────
    let fee_choice = parse_classic_fee_choice(args.fee.as_deref())?;
    let fee_selection =
        resolve_classic_fee_selection(&client, DEFAULT_FEE_STROOPS, fee_choice).await?;
    let fee_per_op = fee_selection.per_op_stroops;
    // Single-operation transaction: the total fee equals the per-operation fee.
    let fee_stroops = i64::from(fee_per_op);

    let native_balance_stroops = account_view
        .balances
        .first()
        .filter(|b| b.asset.asset_type == "native")
        .map(stellar_agent_network::BalanceView::balance_stroops)
        .transpose()?
        .unwrap_or(0);
    let reserves = account_view.reserves_stroops(BASE_RESERVE_STROOPS);
    // saturating_sub: under-reserved accounts yield available = 0, which fails
    // the affordability check as InsufficientBalance rather than underflowing.
    let available = native_balance_stroops.saturating_sub(reserves);
    if available < fee_stroops {
        return Err(ClaimError::from(WalletError::Ledger(
            LedgerError::InsufficientBalance {
                asset: "XLM".to_owned(),
                have: available.to_string(),
                need: fee_stroops.to_string(),
            },
        )));
    }

    // ── Build the unsigned envelope ───────────────────────────────────────────
    // Pass the current on-chain sequence directly; the builder increments it
    // internally (an explicit +1 here would produce CURRENT+2 → TxBadSeq).
    let mut builder = ClassicOpBuilder::new(
        &args.source,
        account_view.sequence_number,
        args.network.passphrase(),
        fee_per_op,
    );
    builder.claim_claimable_balance(&id.to_hex64())?;
    let envelope_xdr = builder.build()?;

    Ok(BuiltClaimEnvelope {
        envelope_xdr,
        balance_id_hex72: id.to_hex72(),
        fee_selection,
    })
}

/// Returns the current Unix time in seconds for predicate evaluation.
fn current_unix_secs() -> Result<u64, ClaimError> {
    let ms = stellar_agent_core::timefmt::now_unix_ms().map_err(|e| {
        WalletError::Internal(InternalError::UnexpectedState {
            detail: format!("system clock unavailable: {e}"),
        })
    })?;
    Ok(ms / 1000)
}

// ─────────────────────────────────────────────────────────────────────────────
// Sign helper
// ─────────────────────────────────────────────────────────────────────────────

/// Signs the given base64 XDR envelope using the configured signer.
///
/// Mirrors the `pay` signer model: `--sign-with-ledger` (hardware; no seed in
/// process memory) or `--secret-env VAR` (the shared mlock-protected software
/// signing ceremony, `resolve_software_signer_from_env`). The public key
/// derived from the signer is compared against `--source` before any signing.
///
/// # Errors
///
/// Propagates `WalletError` from seed parsing, `Wallet::unlock`, the pubkey
/// mismatch check, or the signing call. Returns `AuthError::KeyringLocked` when
/// neither signer flag is provided.
async fn sign_envelope(args: &ClaimArgs, unsigned_xdr: &str) -> Result<String, WalletError> {
    let source = args.source.as_str();
    let passphrase = args.network.passphrase();

    if args.sign_with_ledger {
        let signer = signer_from_ledger(args.account_index, source).await?;
        return attach_signature(unsigned_xdr, &signer, passphrase).await;
    }

    if let Some(ref var_name) = args.secret_env {
        // mlock-protected signing window (shared ceremony, identical
        // discipline to `pay`).
        let signer = resolve_software_signer_from_env(var_name, "claim-commit", None).await?;

        // Public-key verification before signing.
        let signer_pk = signer.public_key().await?;
        let signer_gstrkey = signer_pk.to_string().to_string();
        if signer_gstrkey != source {
            return Err(WalletError::Auth(AuthError::SignerKeyMismatch {
                expected: source.to_owned(),
                got: signer_gstrkey,
            }));
        }

        let signed_xdr = attach_signature(unsigned_xdr, &signer, passphrase).await?;
        drop(signer);

        return Ok(signed_xdr);
    }

    Err(WalletError::Auth(AuthError::KeyringLocked))
}

// ─────────────────────────────────────────────────────────────────────────────
// Submit helper
// ─────────────────────────────────────────────────────────────────────────────

async fn submit_envelope(
    args: &ClaimArgs,
    signed_xdr: &str,
) -> Result<(String, SubmissionResult), WalletError> {
    let client = StellarRpcClient::new(&args.rpc_url)?;
    let timeout = Duration::from_secs(args.timeout_seconds);
    let passphrase = args.network.passphrase();
    let result = submit_transaction_and_wait(
        &client,
        signed_xdr,
        timeout,
        passphrase,
        Some(SubmissionSignerKind::Software),
    )
    .await?;
    Ok((signed_xdr.to_owned(), result))
}

// ─────────────────────────────────────────────────────────────────────────────
// Output helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Renders the typed claim preview to stdout (JSON), before the guards run.
fn render_preview(preview: &ClaimPreview, format: OutputFormat) {
    let envelope = Envelope::ok(serde_json::json!({
        "stage": "preview",
        "balance_id_hex72": &preview.balance_id_hex72,
        "balance_id_strkey": &preview.balance_id_strkey,
        "asset_code": &preview.asset_code,
        "asset_issuer": &preview.asset_issuer,
        "amount_stroops": preview.amount_stroops.to_string(),
        "amount_display": &preview.amount_display,
        "claimants": &preview.claimants,
        "is_claimant": preview.is_claimant,
        "predicate_satisfied": preview.predicate_satisfied,
        "window": &preview.window,
        "clawback_enabled": preview.clawback_enabled,
    }));
    match format {
        OutputFormat::Table => {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            {
                println!(
                    "[preview] balance {}  asset {}  amount {}  is_claimant {}",
                    preview.balance_id_strkey,
                    preview.asset_code.as_deref().unwrap_or("XLM"),
                    preview.amount_display,
                    preview.is_claimant
                );
            }
        }
        _ => render_json(&envelope),
    }
}

/// Builds an error envelope from a [`ClaimError`], preserving its stable
/// `claim.*` / delegated wire code and its (secret-free) display message.
fn claim_error_envelope(err: &ClaimError) -> Envelope<()> {
    Envelope::<()>::err_raw(err.code(), err.to_string())
}

fn print_success(envelope: &Envelope<ClaimResult>, format: OutputFormat) {
    match format {
        OutputFormat::Table =>
        {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            if let Some(result) = &envelope.data {
                match (&result.tx_hash, &result.ledger) {
                    (Some(hash), Some(ledger)) => {
                        use stellar_agent_network::submit::redact_tx_hash;
                        println!(
                            "Claim submitted: tx_hash {}  ledger {}",
                            redact_tx_hash(hash),
                            ledger
                        );
                    }
                    _ => {
                        let prefix: String = result.envelope_xdr.chars().take(32).collect();
                        println!(
                            "[{}] envelope_xdr (first 32 chars): {}...",
                            result.stage, prefix
                        );
                    }
                }
            }
        }
        _ => render_json(envelope),
    }
}

fn print_error(envelope: &Envelope<()>, format: OutputFormat) {
    match format {
        OutputFormat::Table =>
        {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            if let Some(err) = &envelope.error {
                let safe_msg = sanitize_for_table(&err.message);
                println!("Error: {} — {}", err.code, safe_msg);
            }
        }
        _ => render_json(envelope),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics and unwraps are acceptable in unit tests"
    )]

    use super::*;
    use stellar_agent_claimable::entry::TrustlineState;

    const SOURCE_G: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
    const ISSUER_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
    const HEX64: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    fn base_args() -> Vec<String> {
        vec![
            "claim".to_owned(),
            HEX64.to_owned(),
            "--source".to_owned(),
            SOURCE_G.to_owned(),
        ]
    }

    fn try_parse_claim(args: &[String]) -> Result<ClaimArgs, clap::Error> {
        use clap::Parser;
        #[derive(Debug, clap::Parser)]
        struct TestClaim {
            #[command(flatten)]
            args: ClaimArgs,
        }
        TestClaim::try_parse_from(args).map(|t| t.args)
    }

    fn minimal_args() -> ClaimArgs {
        ClaimArgs {
            balance_id: HEX64.to_owned(),
            source: SOURCE_G.to_owned(),
            fee: None,
            secret_env: None,
            sign_with_ledger: false,
            account_index: 0,
            build_only: false,
            sign_only: None,
            submit_only: None,
            network: TargetNetwork::Testnet,
            output: OutputFormat::Json,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            rpc_url: TESTNET_RPC_URL.to_owned(),
        }
    }

    // ── Clap three-stage mutual exclusivity ───────────────────────────────────

    #[test]
    fn clap_build_only_and_sign_only_are_mutually_exclusive() {
        let mut args = base_args();
        args.extend([
            "--build-only".to_owned(),
            "--sign-only".to_owned(),
            "AAAA==".to_owned(),
        ]);
        let err = try_parse_claim(&args).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn clap_build_only_and_submit_only_are_mutually_exclusive() {
        let mut args = base_args();
        args.extend([
            "--build-only".to_owned(),
            "--submit-only".to_owned(),
            "AAAA==".to_owned(),
        ]);
        let err = try_parse_claim(&args).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn clap_sign_only_and_submit_only_are_mutually_exclusive() {
        let mut args = base_args();
        args.extend([
            "--sign-only".to_owned(),
            "AAAA==".to_owned(),
            "--submit-only".to_owned(),
            "AAAA==".to_owned(),
        ]);
        let err = try_parse_claim(&args).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn clap_secret_env_and_sign_with_ledger_are_mutually_exclusive() {
        let mut args = base_args();
        args.extend([
            "--secret-env".to_owned(),
            "MY_SECRET".to_owned(),
            "--sign-with-ledger".to_owned(),
        ]);
        let err = try_parse_claim(&args).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn clap_base_args_parse_and_default_to_full_pipeline() {
        let parsed = try_parse_claim(&base_args()).expect("base args must parse");
        assert_eq!(parsed.balance_id, HEX64);
        assert_eq!(parsed.source, SOURCE_G);
        assert!(!parsed.build_only);
        assert!(parsed.sign_only.is_none());
        assert!(parsed.submit_only.is_none());
        assert_eq!(parsed.network, TargetNetwork::Testnet);
    }

    // ── Trustline guard refusal paths (hand-built TrustlineState) ─────────────
    //
    // TrustlineState is a plain (non-exhaustive-free) struct, so the trustline
    // guard's refusal codes are exercised directly here. The claimant and
    // predicate guards operate on `ClaimPreview`, which is `#[non_exhaustive]`
    // and therefore only constructible inside `stellar-agent-claimable`, where
    // those guards are already unit-tested.

    #[test]
    fn check_trustline_missing_refuses() {
        let state = TrustlineState {
            exists: false,
            authorized: false,
            limit: 0,
            balance: 0,
        };
        let err = check_trustline(&state, Some("USDC"), Some(ISSUER_G), 100)
            .expect_err("missing trustline must refuse");
        assert_eq!(err.code(), "claim.trustline_missing");
    }

    #[test]
    fn check_trustline_not_authorized_refuses() {
        let state = TrustlineState {
            exists: true,
            authorized: false,
            limit: 1_000,
            balance: 0,
        };
        let err = check_trustline(&state, Some("USDC"), Some(ISSUER_G), 100)
            .expect_err("unauthorized trustline must refuse");
        assert_eq!(err.code(), "claim.trustline_not_authorized");
    }

    #[test]
    fn check_trustline_limit_refuses() {
        let state = TrustlineState {
            exists: true,
            authorized: true,
            limit: 1_000,
            balance: 950,
        };
        let err = check_trustline(&state, Some("USDC"), Some(ISSUER_G), 100)
            .expect_err("amount over headroom must refuse");
        assert_eq!(err.code(), "claim.trustline_limit");
    }

    // ── Fee-affordability error mapping ───────────────────────────────────────

    #[test]
    fn fee_unaffordable_maps_to_insufficient_balance() {
        let err = ClaimError::from(WalletError::Ledger(LedgerError::InsufficientBalance {
            asset: "XLM".to_owned(),
            have: "0".to_owned(),
            need: "100".to_owned(),
        }));
        assert_eq!(err.code(), "ledger.insufficient_balance");
    }

    // ── Invalid balance id maps to the claim wire code ────────────────────────

    #[test]
    fn invalid_balance_id_error_code() {
        let err = BalanceId::parse("not-a-balance-id").expect_err("must refuse");
        let envelope = claim_error_envelope(&err);
        assert_eq!(
            envelope.error.as_ref().map(|e| e.code.as_str()),
            Some("claim.invalid_balance_id")
        );
    }

    // ── Mainnet rejected at run boundary ──────────────────────────────────────

    /// Mainnet is rejected at the `run` boundary before any RPC call. The
    /// non-routable RPC address ensures an accidental call would fail with a
    /// connection error rather than silently succeeding.
    #[tokio::test]
    async fn mainnet_rejected_at_run_boundary() {
        let mut args = minimal_args();
        args.network = TargetNetwork::Mainnet;
        args.rpc_url = "http://127.0.0.1:1".to_owned();
        let exit = run(&args).await;
        assert_eq!(exit, 1, "mainnet must exit with code 1");
    }
}
