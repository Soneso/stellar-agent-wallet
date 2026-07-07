//! `stellar-agent pay` subcommand — payment spine.
//!
//! Supports three execution stages that may be chained or used independently:
//!
//! 1. **Build** (`--build-only`) — constructs the transaction envelope, runs
//!    SEP-29 memo-required enforcement, and emits unsigned base64 XDR.
//! 2. **Sign** (`--sign-only <base64-xdr>`) — signs a previously-built envelope
//!    and emits signed base64 XDR.
//! 3. **Submit** (`--submit-only <base64-xdr>`) — submits a signed envelope and
//!    polls until confirmation.
//!
//! Default (no stage flag): runs all three stages atomically.
//!
//! # Stage flag mutual exclusivity
//!
//! `--build-only`, `--sign-only`, and `--submit-only` are structurally
//! mutually exclusive via a `clap` argument group. Passing more than one
//! is a parse error before `run` is called.
//!
//! # Mainnet rejection
//!
//! `--network testnet` is the only accepted value. Mainnet is structurally
//! rejected at two layers:
//! - CLI: the `TargetNetwork::Mainnet` variant returns
//!   `network.mainnet_write_forbidden` before any RPC call.
//! - Submit layer: `submit_transaction_and_wait` rejects mainnet-looking URLs
//!   as a defence-in-depth measure.
//!
//! # Secret-material policy
//!
//! `--secret-env VAR` reads the secret key from the environment variable
//! named `VAR` through the shared
//! [`crate::common::signer_ceremony::resolve_software_signer_from_env`]
//! ceremony: the value is wrapped in `Zeroizing<String>` immediately, loaded
//! into a [`stellar_agent_core::wallet::Wallet`] via
//! [`stellar_agent_core::wallet::Wallet::unlock`], and consumed by
//! [`stellar_agent_network::signing::wallet::signer_from_wallet`].  The
//! `LockedSeed` (mlock-protected) is held only for the duration of the parse
//! and derive; the `SoftwareSigningKey` returned to this module drops at the
//! end of the signing block, ensuring zeroization fires on every exit path.
//!
//! # mlock-protected signing window
//!
//! The `--secret-env` path routes through the shared ceremony
//! (`Wallet::unlock` → `LockedSeed` → `signer_from_wallet` → dispose) →
//! `attach_signature` → drop. The `--sign-with-ledger` path uses
//! `signer_from_ledger` (hardware signer; no seed ever in memory).
//!
//! # Behavior
//!
//! All network calls go through Stellar RPC. SEP-29 on-chain data-entry
//! enforcement runs before signing. Ledger signing is available via
//! `--sign-with-ledger`. The `--secret-env` path uses an mlock-protected
//! signing window.

use std::time::Duration;

use clap::{ArgGroup, Args};
use stellar_agent_core::StellarAmount;
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{AuthError, NetworkError, ValidationError, WalletError};
use stellar_xdr::Memo;

use stellar_agent_network::builder::{Asset, ClassicOpBuilder};
use stellar_agent_network::signing::Signer;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::signing::source::signer_from_ledger;
use stellar_agent_network::{
    ClassicFeeSelection, StellarRpcClient, SubmissionResult, SubmissionSignerKind,
    parse_classic_fee_choice, parse_memo_fields, resolve_classic_fee_selection,
    submit_transaction_and_wait,
};

use crate::common::network::TargetNetwork;
use crate::common::render::{render_json, sanitize_for_table};
use crate::common::signer_ceremony::{SignerCeremonyOutcome, resolve_software_signer_from_env};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default fee per operation in stroops (100 stroops × 1 op = 100 stroops).
const DEFAULT_FEE_STROOPS: u32 = 100;

/// AGPL-3.0 disclosure text emitted to stderr when `--use-oz-relayer` is set.
///
/// This is the informed-consent banner. The text is conditional (WOULD subject
/// / links no AGPL code) because the path discloses and then REFUSES — no
/// relayer actually runs at this point. The phrase "links no AGPL code" is
/// legally load-bearing and must not be changed without a decision record.
pub const RELAYER_AGPL_DISCLOSURE: &str = "\
NOTICE: --use-oz-relayer is the opt-in for routing submission through a \
self-hosted OpenZeppelin Relayer Channels Plugin. That relayer is AGPL-3.0; \
self-hosting it WOULD subject your deployment to AGPL-3.0 source-disclosure \
obligations. This wallet is Apache-2.0 and links no AGPL code. Relayer submission \
is not implemented in this build; the default in-process path requires no such \
dependency \u{2014} re-run without --use-oz-relayer.";

/// Default submission timeout in seconds.
const DEFAULT_TIMEOUT_SECONDS: u64 = 60;

/// Stellar testnet RPC endpoint (SDF operated).
const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";

// ─────────────────────────────────────────────────────────────────────────────
// PayResult — the structured success payload
// ─────────────────────────────────────────────────────────────────────────────

/// Structured payload returned in the JSON envelope on a successful payment.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PayResult {
    /// Base64-encoded signed `TransactionEnvelope` XDR.
    ///
    /// Present for build-only and sign-only stages; the full pipeline also
    /// includes this field so callers have the XDR for auditing.
    pub envelope_xdr: String,

    /// Transaction hash (64-character hex), present after submission.
    ///
    /// Absent for `--build-only` and `--sign-only`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,

    /// Ledger sequence number, present after confirmation.
    ///
    /// Absent for `--build-only` and `--sign-only`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ledger: Option<u32>,

    /// The stage that produced this result.
    pub stage: String,

    /// Selected per-operation fee in stroops.
    ///
    /// Encoded as a decimal string on the wire (`serde(with =
    /// "stellar_agent_core::wire_stroops::u32_opt")`). The Rust field type
    /// stays `Option<u32>`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "stellar_agent_core::wire_stroops::u32_opt"
    )]
    pub selected_fee_per_op_stroops: Option<u32>,

    /// Fee selection source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_fee_percentile: Option<String>,
}

#[derive(Debug, Clone)]
struct BuiltPaymentEnvelope {
    envelope_xdr: String,
    fee_selection: ClassicFeeSelection,
}

// ─────────────────────────────────────────────────────────────────────────────
// PayArgs
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `pay` subcommand.
///
/// Stage flags (`--build-only`, `--sign-only`, `--submit-only`) are
/// mutually exclusive via an `ArgGroup`. Memo flags are also mutually
/// exclusive via a separate `ArgGroup`.
#[non_exhaustive]
#[derive(Debug, Args)]
#[command(
    group(ArgGroup::new("stage").args(["build_only", "sign_only", "submit_only"]).required(false)),
    group(ArgGroup::new("memo_group").args(["memo_text", "memo_id", "memo_hash_hex", "memo_return_hex"]).required(false)),
    group(ArgGroup::new("signer_group").args(["secret_env", "sign_with_ledger"]).required(false)),
)]
pub struct PayArgs {
    /// Destination account G-strkey.
    #[arg(value_name = "DESTINATION")]
    pub destination: String,

    /// Amount to send with explicit units, e.g. `"10 XLM"` or `"10.0000000 XLM"`.
    /// For non-native assets: `"10.5 USDC"` etc. Raw stroop numeric strings
    /// are not accepted; use `"0.0000001 XLM"` for the minimum unit.
    #[arg(value_name = "AMOUNT")]
    pub amount: String,

    /// Asset descriptor: `native`, `XLM`, or `CODE:ISSUER_GSTRKEY`.
    /// Defaults to `native`.
    #[arg(value_name = "ASSET", default_value = "native")]
    pub asset: String,

    /// Memo text (UTF-8, ≤28 bytes).
    #[arg(long, value_name = "STRING", group = "memo_group")]
    pub memo_text: Option<String>,

    /// Memo ID (u64 decimal).
    #[arg(long, value_name = "U64", group = "memo_group")]
    pub memo_id: Option<u64>,

    /// Memo hash (64 hex characters → 32 bytes).
    #[arg(long = "memo-hash", value_name = "64_HEX", group = "memo_group")]
    pub memo_hash_hex: Option<String>,

    /// Memo return hash (64 hex characters → 32 bytes).
    #[arg(long = "memo-return", value_name = "64_HEX", group = "memo_group")]
    pub memo_return_hex: Option<String>,

    /// Classic fee per operation: `<stroops>`, `auto`, or `auto:pNN`.
    #[arg(long, value_name = "STROOPS|auto[:pNN]")]
    pub fee: Option<String>,

    /// Source account G-strkey. Required for signing.
    #[arg(long, value_name = "G_STRKEY")]
    pub source: Option<String>,

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

    /// Network to target. `mainnet` parses but is structurally refused before
    /// any RPC call or signing (wire code `network.mainnet_write_forbidden`).
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,

    /// Submission timeout in seconds. Default: 60.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,

    /// Override the Stellar RPC endpoint URL.
    #[arg(
        long,
        default_value = TESTNET_RPC_URL,
        value_name = "URL"
    )]
    pub rpc_url: String,

    /// Opt in to routing submission through a self-hosted OZ Relayer Channels
    /// Plugin (AGPL-3.0); not implemented in this build — emits an AGPL-3.0
    /// disclosure and declines the operation.
    #[arg(long, default_value_t = false)]
    pub use_oz_relayer: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// run — main dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Runs the `pay` subcommand.
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
pub async fn run(args: &PayArgs) -> i32 {
    // ── Mainnet structural rejection (first layer) ────────────────────────────
    if args.network == TargetNetwork::Mainnet {
        let err = WalletError::Network(NetworkError::MainnetWriteForbidden);
        let envelope = Envelope::<()>::err(&err);
        print_error(&envelope, args.output);
        return 1;
    }

    // ── OZ Relayer opt-in gate ────────────────────────────────────────────────
    // Fires AFTER network-validation but BEFORE any keyring/signer touch or
    // RPC client construction — the refuse path provably loads no secret and
    // makes no network call.
    if let Err(e) = check_relayer_opt_in(args) {
        let envelope = Envelope::<()>::err(&e);
        print_error(&envelope, args.output);
        return 1;
    }

    // Determine execution stage.
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

async fn run_build_only(args: &PayArgs) -> i32 {
    match build_unsigned_envelope(args).await {
        Ok(built) => {
            let result = PayResult {
                envelope_xdr: built.envelope_xdr,
                tx_hash: None,
                ledger: None,
                stage: "build".to_owned(),
                selected_fee_per_op_stroops: Some(built.fee_selection.per_op_stroops),
                selected_fee_percentile: Some(built.fee_selection.selected_fee_percentile),
            };
            let envelope = Envelope::ok(result);
            print_success(&envelope, args.output);
            0
        }
        Err(e) => {
            let envelope = Envelope::<()>::err(&e);
            print_error(&envelope, args.output);
            1
        }
    }
}

async fn run_sign_only(args: &PayArgs, unsigned_xdr: &str) -> i32 {
    match sign_envelope(args, unsigned_xdr).await {
        Ok(signed_xdr) => {
            let result = PayResult {
                envelope_xdr: signed_xdr,
                tx_hash: None,
                ledger: None,
                stage: "sign".to_owned(),
                selected_fee_per_op_stroops: None,
                selected_fee_percentile: None,
            };
            let envelope = Envelope::ok(result);
            print_success(&envelope, args.output);
            0
        }
        Err(e) => {
            let envelope = Envelope::<()>::err(&e);
            print_error(&envelope, args.output);
            1
        }
    }
}

async fn run_submit_only(args: &PayArgs, signed_xdr: &str) -> i32 {
    match submit_envelope(args, signed_xdr).await {
        Ok((signed_xdr, sub_result)) => {
            let result = PayResult {
                envelope_xdr: signed_xdr,
                tx_hash: Some(sub_result.tx_hash.clone()),
                ledger: Some(sub_result.ledger),
                stage: "submit".to_owned(),
                selected_fee_per_op_stroops: None,
                selected_fee_percentile: None,
            };
            let envelope = Envelope::ok(result);
            print_success(&envelope, args.output);
            0
        }
        Err(e) => {
            let envelope = Envelope::<()>::err(&e);
            print_error(&envelope, args.output);
            1
        }
    }
}

async fn run_full_pipeline(args: &PayArgs) -> i32 {
    // Require both source and a signer for the full pipeline.
    if args.source.is_none() {
        let err =
            WalletError::Validation(stellar_agent_core::error::ValidationError::AddressInvalid {
                input: "--source is required for signing".to_owned(),
            });
        let envelope = Envelope::<()>::err(&err);
        print_error(&envelope, args.output);
        return 1;
    }

    // 1. Build (includes SEP-29 check).
    let built = match build_unsigned_envelope(args).await {
        Ok(built) => built,
        Err(e) => {
            let envelope = Envelope::<()>::err(&e);
            print_error(&envelope, args.output);
            return 1;
        }
    };
    let unsigned_xdr = built.envelope_xdr.clone();
    let fee_selection = built.fee_selection;

    // 2. Sign.
    let signed_xdr = match sign_envelope(args, &unsigned_xdr).await {
        Ok(xdr) => xdr,
        Err(e) => {
            let envelope = Envelope::<()>::err(&e);
            print_error(&envelope, args.output);
            return 1;
        }
    };

    // 3. Submit.
    match submit_envelope(args, &signed_xdr).await {
        Ok((xdr, sub_result)) => {
            let result = PayResult {
                envelope_xdr: xdr,
                tx_hash: Some(sub_result.tx_hash.clone()),
                ledger: Some(sub_result.ledger),
                stage: "build+sign+submit".to_owned(),
                selected_fee_per_op_stroops: Some(fee_selection.per_op_stroops),
                selected_fee_percentile: Some(fee_selection.selected_fee_percentile),
            };
            let envelope = Envelope::ok(result);
            print_success(&envelope, args.output);
            0
        }
        Err(e) => {
            let envelope = Envelope::<()>::err(&e);
            print_error(&envelope, args.output);
            1
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Build helper
// ─────────────────────────────────────────────────────────────────────────────

/// Constructs and returns the unsigned transaction envelope XDR.
///
/// Runs SEP-29 memo-required check before building.
async fn build_unsigned_envelope(args: &PayArgs) -> Result<BuiltPaymentEnvelope, WalletError> {
    let source = args.source.as_deref().ok_or_else(|| {
        WalletError::Validation(stellar_agent_core::error::ValidationError::AddressInvalid {
            input: "--source is required for building a transaction".to_owned(),
        })
    })?;

    let client = StellarRpcClient::new(&args.rpc_url)?;
    let fee_choice = parse_classic_fee_choice(args.fee.as_deref())?;
    let fee_selection =
        resolve_classic_fee_selection(&client, DEFAULT_FEE_STROOPS, fee_choice).await?;

    // Fetch source account to get sequence number and verify it exists.
    // Pass empty slice: pay only needs the account sequence number (native balance
    // is sufficient); no trustlines are queried here.
    let source_account = stellar_agent_network::fetch_account(&client, source, &[]).await?;
    // Pass the current on-chain sequence directly; `stellar_baselib::TransactionBuilder::build`
    // calls `Account::increment_sequence_number` internally. An explicit +1
    // here would produce CURRENT+2 → TxBadSeq.
    let sequence_number = source_account.sequence_number;

    // Boundary discipline: parse_with_unit is the only permitted parser for
    // human-supplied amounts at CLI boundaries. Raw stroop numeric strings are
    // explicitly rejected to enforce unit discipline. If stroop-level input is
    // required in the future, add a dedicated `--amount-in-stroops` flag.
    let amount = StellarAmount::parse_with_unit(&args.amount).map_err(|_| {
        WalletError::Validation(ValidationError::AmountMalformed {
            input: args.amount.clone(),
        })
    })?;

    // Parse asset.
    let asset = Asset::parse(&args.asset)?;

    // Parse memo.
    let memo = parse_memo(args)?;
    let memo_present = !matches!(memo, Memo::None);

    // SEP-29: check memo-required BEFORE signing.
    // CLI has no secondary/oracle RPC — pass `None`; cross-RPC consistency is
    // the MCP simulate-path responsibility.
    stellar_agent_network::sep29::check_memo_required(
        &client,
        None,
        &args.destination,
        memo_present,
    )
    .await?;

    // Build.
    let mut builder = ClassicOpBuilder::new(
        source,
        sequence_number,
        args.network.passphrase(),
        fee_selection.per_op_stroops,
    );

    builder.payment(&args.destination, amount, &asset)?;
    builder.memo(&memo)?;

    let envelope_xdr = builder.build()?;

    Ok(BuiltPaymentEnvelope {
        envelope_xdr,
        fee_selection,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Sign helper
// ─────────────────────────────────────────────────────────────────────────────

/// Signs the given base64 XDR envelope using the configured signer.
///
/// # Signing path selection
///
/// - `--sign-with-ledger`: delegates to `signer_from_ledger` (hardware; no
///   seed ever held in process memory).
/// - `--secret-env VAR`: derives a `SoftwareSigningKey` via the shared
///   [`crate::common::signer_ceremony::resolve_software_signer_from_env`]
///   ceremony (mlock-protected `Wallet` unlock, `signer_from_wallet`, wallet
///   dispose), then calls `attach_signature` once and drops the key.
///
/// # Public-key verification
///
/// For the `--secret-env` path, the public key derived from the seed is
/// compared against `--source` BEFORE any signing or RPC call, mirroring
/// the invariant in `signing::source::signer_from_s_strkey`.
///
/// # Errors
///
/// Propagates `WalletError` from seed parsing, Wallet::unlock, signing, or
/// mlock failures.
async fn sign_envelope(args: &PayArgs, unsigned_xdr: &str) -> Result<String, WalletError> {
    let source = args.source.as_deref().ok_or_else(|| {
        WalletError::Validation(stellar_agent_core::error::ValidationError::AddressInvalid {
            input: "--source is required for signing".to_owned(),
        })
    })?;

    let passphrase = args.network.passphrase();

    if args.sign_with_ledger {
        // Hardware path: seed never enters process memory.
        let signer = signer_from_ledger(args.account_index, source).await?;
        return attach_signature(unsigned_xdr, &signer, passphrase).await;
    }

    if let Some(ref var_name) = args.secret_env {
        // mlock-protected signing window (shared ceremony):
        //
        // 1. Derive the SoftwareSigningKey via
        //    `resolve_software_signer_from_env` (env -> Zeroizing<String> ->
        //    seed Zeroizing<[u8; 32]> -> zeroize PrivateKey.0 residue ->
        //    Wallet::unlock -> signer_from_wallet -> wallet.dispose()).
        // 2. Verify the derived public key matches --source before signing.
        // 3. attach_signature exactly once.
        // 4. Drop SoftwareSigningKey -> SecretBox zeroised.
        // `pay` has no audit-writer infrastructure (no `--profile` flag; no
        // audit log is opened anywhere in this command): a degraded unlock
        // is surfaced only via `Wallet::unlock`'s own `tracing::warn!`.
        let SignerCeremonyOutcome {
            signer,
            mlock_degradation: _,
        } = resolve_software_signer_from_env(var_name, "pay-commit", None).await?;

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
    args: &PayArgs,
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
// Memo parsing
// ─────────────────────────────────────────────────────────────────────────────

/// Parses memo arguments into an XDR `Memo`.
///
/// Delegates to [`stellar_agent_network::parse_memo_fields`], the shared
/// implementation for both the CLI pay command and the `stellar_pay` MCP tool.
fn parse_memo(args: &PayArgs) -> Result<Memo, WalletError> {
    parse_memo_fields(
        args.memo_text.as_deref(),
        args.memo_id,
        args.memo_hash_hex.as_deref(),
        args.memo_return_hex.as_deref(),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Relayer opt-in gate
// ─────────────────────────────────────────────────────────────────────────────

/// Checks whether `--use-oz-relayer` was set and, if so, emits the AGPL-3.0
/// disclosure banner to stderr and returns a typed refuse error.
///
/// This function is the **sole** enforcement point for the informed-consent
/// discipline. It must be called AFTER network/arg validation gates (e.g.
/// mainnet reject) but BEFORE any keyring/signer touch or RPC client
/// construction, so that the refuse path provably loads no secret and performs
/// no network call.
///
/// When `args.use_oz_relayer` is `false`, returns `Ok(())` and the call site
/// continues normally.
///
/// # Errors
///
/// Returns `Err(WalletError::Validation(ValidationError::RelayerNotImplemented))`
/// when `args.use_oz_relayer` is `true`.
pub fn check_relayer_opt_in(args: &PayArgs) -> Result<(), WalletError> {
    if args.use_oz_relayer {
        #[allow(
            clippy::print_stderr,
            reason = "AGPL-3.0 disclosure for the relayer opt-in"
        )]
        {
            eprintln!();
            eprintln!("{}", RELAYER_AGPL_DISCLOSURE);
            eprintln!();
        }
        return Err(WalletError::Validation(
            ValidationError::RelayerNotImplemented,
        ));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Output helpers
// ─────────────────────────────────────────────────────────────────────────────

fn print_success(envelope: &Envelope<PayResult>, format: OutputFormat) {
    match format {
        OutputFormat::Table => {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            if let Some(result) = &envelope.data {
                match (&result.tx_hash, &result.ledger) {
                    (Some(hash), Some(ledger)) => {
                        // Use redact_tx_hash from stellar-agent-network::submit.
                        use stellar_agent_network::submit::redact_tx_hash;
                        let selected_fee = crate::render::table::render_selected_fee_line(
                            result.selected_fee_per_op_stroops,
                            result.selected_fee_percentile.as_deref(),
                        );
                        println!(
                            "Payment submitted: tx_hash {}  ledger {}\n{}",
                            redact_tx_hash(hash),
                            ledger,
                            selected_fee
                        );
                    }
                    _ => {
                        // Build or sign stage. Use chars().take(32) to avoid a
                        // byte-boundary panic on multi-byte UTF-8 input.
                        let prefix: String = result.envelope_xdr.chars().take(32).collect();
                        let selected_fee = crate::render::table::render_selected_fee_line(
                            result.selected_fee_per_op_stroops,
                            result.selected_fee_percentile.as_deref(),
                        );
                        println!(
                            "[{}] envelope_xdr (first 32 chars): {}...\n{}",
                            result.stage, prefix, selected_fee
                        );
                    }
                }
            }
        }
        // Json and all unknown formats: delegate to shared render_json.
        _ => render_json(envelope),
    }
}

fn print_error(envelope: &Envelope<()>, format: OutputFormat) {
    match format {
        OutputFormat::Table => {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            if let Some(err) = &envelope.error {
                // Sanitize to strip terminal-escape sequences from the message.
                let safe_msg = sanitize_for_table(&err.message);
                println!("Error: {} — {}", err.code, safe_msg);
            }
        }
        // Json and all unknown formats: delegate to shared render_json.
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
        reason = "test-only; panics and unwraps are acceptable in unit tests"
    )]

    use std::sync::Arc;

    use super::*;
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers::method};

    const SOURCE_G: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
    const DEST_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

    struct PayBuildRpcResponder {
        account_key_xdr: String,
        account_xdr: String,
        fee_stats: Arc<serde_json::Value>,
    }

    impl PayBuildRpcResponder {
        fn new(account_key_xdr: String, account_xdr: String, fee_stats: serde_json::Value) -> Self {
            Self {
                account_key_xdr,
                account_xdr,
                fee_stats: Arc::new(fee_stats),
            }
        }
    }

    #[async_trait::async_trait]
    impl Respond for PayBuildRpcResponder {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let request_value = serde_json::from_slice::<serde_json::Value>(&request.body)
                .unwrap_or_else(|_| serde_json::json!({}));
            let req_id = request_value
                .get("id")
                .cloned()
                .unwrap_or_else(|| serde_json::json!(1));
            let method = request_value
                .get("method")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");

            let result = match method {
                "getFeeStats" => (*self.fee_stats).clone(),
                "getLedgerEntries" => {
                    let body = String::from_utf8_lossy(&request.body);
                    if body.contains(&self.account_key_xdr) {
                        serde_json::json!({
                            "entries": [{
                                "key": self.account_key_xdr,
                                "xdr": self.account_xdr,
                                "lastModifiedLedgerSeq": 1000
                            }],
                            "latestLedger": 1001
                        })
                    } else {
                        serde_json::json!({
                            "entries": [],
                            "latestLedger": 1001
                        })
                    }
                }
                _ => serde_json::json!({}),
            };

            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": result,
                }))
                .insert_header("content-type", "application/json")
        }
    }

    fn account_entry_xdr_with_balance(account_id: &str, balance_stroops: i64) -> String {
        use stellar_xdr::{
            AccountEntry, AccountEntryExt, AccountId, LedgerEntryData, Limits, PublicKey,
            SequenceNumber, String32, Thresholds, Uint256, WriteXdr,
        };
        let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(account_id)
            .expect("valid account_id")
            .0;
        let entry = AccountEntry {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes))),
            balance: balance_stroops,
            seq_num: SequenceNumber(100),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: String32::default(),
            thresholds: Thresholds([1, 0, 0, 0]),
            signers: vec![].try_into().expect("empty signers"),
            ext: AccountEntryExt::V0,
        };
        LedgerEntryData::Account(entry)
            .to_xdr_base64(Limits::none())
            .expect("XDR encoding must succeed")
    }

    fn account_ledger_key_xdr(account_id: &str) -> String {
        use stellar_xdr::{
            AccountId, LedgerKey, LedgerKeyAccount, Limits, PublicKey, Uint256, WriteXdr,
        };
        let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(account_id)
            .expect("valid account_id")
            .0;
        let key = LedgerKey::Account(LedgerKeyAccount {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes))),
        });
        key.to_xdr_base64(Limits::none())
            .expect("XDR encoding must succeed")
    }

    fn fee_stat_json(p95: &str, p99: &str) -> serde_json::Value {
        serde_json::json!({
            "max": "1000",
            "min": "100",
            "mode": "100",
            "p10": "100",
            "p20": "110",
            "p30": "120",
            "p40": "130",
            "p50": "140",
            "p60": "150",
            "p70": "160",
            "p80": "170",
            "p90": "180",
            "p95": p95,
            "p99": p99,
            "transactionCount": "12",
            "ledgerCount": "5"
        })
    }

    fn fee_stats_result(p95: &str, p99: &str) -> serde_json::Value {
        serde_json::json!({
            "sorobanInclusionFee": fee_stat_json("300", "400"),
            "inclusionFee": fee_stat_json(p95, p99),
            "latestLedger": "12345"
        })
    }

    fn tx_fee_from_envelope_xdr(envelope_xdr: &str) -> u32 {
        use stellar_xdr::{Limits, ReadXdr, TransactionEnvelope};

        let envelope = TransactionEnvelope::from_xdr_base64(envelope_xdr, Limits::none())
            .expect("valid transaction envelope");
        assert!(
            matches!(envelope, TransactionEnvelope::Tx(_)),
            "expected v1 transaction envelope"
        );
        if let TransactionEnvelope::Tx(env) = envelope {
            env.tx.fee
        } else {
            0
        }
    }

    async fn mount_pay_build_rpc(p95: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(PayBuildRpcResponder::new(
                account_ledger_key_xdr(SOURCE_G),
                account_entry_xdr_with_balance(SOURCE_G, 100_000_000_000),
                fee_stats_result(p95, "999"),
            ))
            .mount(&server)
            .await;
        server
    }

    // ── Clap three-stage and memo/signer mutex tests ─────────────────────────

    /// Helper: build a minimal arg list for PayArgs.
    fn base_args() -> Vec<&'static str> {
        vec![
            "pay",
            "GDEST1234567890ABCDEF1234567890ABCDEF1234567890ABCDEFGH",
            "10 XLM",
        ]
    }

    /// Parse `PayArgs` from a vec of string slices via the Command interface.
    fn try_parse_pay(args: &[&str]) -> Result<PayArgs, clap::Error> {
        use clap::Parser;

        // We need a wrapper struct to act as the top-level parser.
        #[derive(Debug, clap::Parser)]
        struct TestPay {
            #[command(flatten)]
            args: PayArgs,
        }

        TestPay::try_parse_from(args).map(|t| t.args)
    }

    #[test]
    fn clap_build_only_and_sign_only_are_mutually_exclusive() {
        let mut args = base_args();
        args.extend(["--build-only", "--sign-only", "AAAAAA=="]);
        let result = try_parse_pay(&args);
        assert!(
            result.is_err(),
            "--build-only + --sign-only must conflict: {result:?}"
        );
        let err = result.unwrap_err();
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::ArgumentConflict,
            "expected ArgumentConflict, got: {err}"
        );
    }

    #[test]
    fn clap_build_only_and_submit_only_are_mutually_exclusive() {
        let mut args = base_args();
        args.extend(["--build-only", "--submit-only", "AAAAAA=="]);
        let result = try_parse_pay(&args);
        assert!(
            result.is_err(),
            "--build-only + --submit-only must conflict"
        );
        assert_eq!(
            result.unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn clap_sign_only_and_submit_only_are_mutually_exclusive() {
        let mut args = base_args();
        args.extend(["--sign-only", "AAAAAA==", "--submit-only", "AAAAAA=="]);
        let result = try_parse_pay(&args);
        assert!(result.is_err(), "--sign-only + --submit-only must conflict");
        assert_eq!(
            result.unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn clap_memo_text_and_memo_id_are_mutually_exclusive() {
        let mut args = base_args();
        args.extend(["--memo-text", "hello", "--memo-id", "42"]);
        let result = try_parse_pay(&args);
        assert!(result.is_err(), "--memo-text + --memo-id must conflict");
        assert_eq!(
            result.unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn clap_memo_text_and_memo_hash_are_mutually_exclusive() {
        let mut args = base_args();
        let hash = "0".repeat(64);
        args.push("--memo-text");
        args.push("hello");
        args.push("--memo-hash");
        let args_owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let mut args_owned2 = args_owned;
        args_owned2.push(hash);
        let result: Result<PayArgs, clap::Error> = {
            use clap::Parser;
            #[derive(Debug, clap::Parser)]
            struct TestPay {
                #[command(flatten)]
                args: PayArgs,
            }
            TestPay::try_parse_from(&args_owned2).map(|t| t.args)
        };
        assert!(result.is_err(), "--memo-text + --memo-hash must conflict");
        assert_eq!(
            result.unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn clap_secret_env_and_sign_with_ledger_are_mutually_exclusive() {
        let mut args = base_args();
        args.extend(["--secret-env", "MY_SECRET", "--sign-with-ledger"]);
        let result = try_parse_pay(&args);
        assert!(
            result.is_err(),
            "--secret-env + --sign-with-ledger must conflict"
        );
        assert_eq!(
            result.unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    // ── Network / amount tests ────────────────────────────────────────────────

    #[test]
    fn target_network_variant_rejects_unknown_network_string() {
        use std::str::FromStr;
        assert!(TargetNetwork::from_str("futurenet").is_err());
    }

    #[test]
    fn target_network_variant_round_trips() {
        use std::str::FromStr;
        assert_eq!(
            TargetNetwork::from_str("testnet").unwrap(),
            TargetNetwork::Testnet
        );
        assert_eq!(
            TargetNetwork::from_str("TESTNET").unwrap(),
            TargetNetwork::Testnet
        );
        assert_eq!(
            TargetNetwork::from_str("mainnet").unwrap(),
            TargetNetwork::Mainnet
        );
    }

    /// The mainnet-write-forbidden error code is `"network.mainnet_write_forbidden"`.
    ///
    /// This test would fail if the `MainnetWriteForbidden` variant were removed
    /// or its wire code changed, ensuring the refusal produces the correct
    /// structured error downstream tooling relies on.
    #[test]
    fn mainnet_write_forbidden_error_has_correct_code() {
        let err = WalletError::Network(NetworkError::MainnetWriteForbidden);
        assert_eq!(
            err.code(),
            "network.mainnet_write_forbidden",
            "wire code must be 'network.mainnet_write_forbidden'"
        );
        assert!(
            matches!(
                err,
                WalletError::Network(NetworkError::MainnetWriteForbidden)
            ),
            "must be WalletError::Network(NetworkError::MainnetWriteForbidden)"
        );
    }

    /// Mainnet is rejected at the `run` boundary before any RPC call is made,
    /// returning exit code 1.
    ///
    /// The test does not start a mock server; using a non-routable address
    /// (127.0.0.1:1) ensures any accidental RPC call would fail with a
    /// connection error rather than silently succeeding.
    #[tokio::test]
    async fn mainnet_rejected_at_run_boundary() {
        let args = PayArgs {
            destination: "GABC1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGH".to_owned(),
            amount: "10 XLM".to_owned(),
            asset: "native".to_owned(),
            memo_text: None,
            memo_id: None,
            memo_hash_hex: None,
            memo_return_hex: None,
            fee: None,
            source: Some("GABC1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGH".to_owned()),
            secret_env: None,
            sign_with_ledger: false,
            account_index: 0,
            build_only: false,
            sign_only: None,
            submit_only: None,
            network: TargetNetwork::Mainnet,
            output: OutputFormat::Json,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            // Non-routable: any RPC call would result in a connection error,
            // making an accidentally-passing test impossible.
            rpc_url: "http://127.0.0.1:1".to_owned(),
            use_oz_relayer: false,
        };
        let exit = run(&args).await;
        assert_eq!(exit, 1, "mainnet must exit with code 1");
    }

    // Note: decode_32_hex_bytes and hex_nibble are now in
    // stellar_agent_network::memo; their unit tests live there.
    // The parse_memo tests below exercise the thin CLI wrapper.

    #[test]
    fn parse_memo_none() {
        let args = minimal_args();
        let memo = parse_memo(&args).unwrap();
        assert!(matches!(memo, Memo::None));
    }

    #[test]
    fn parse_memo_text() {
        let mut args = minimal_args();
        args.memo_text = Some("hello".to_owned());
        let memo = parse_memo(&args).unwrap();
        assert!(matches!(memo, Memo::Text(_)));
    }

    #[test]
    fn parse_memo_text_too_long() {
        let mut args = minimal_args();
        args.memo_text = Some("a".repeat(29));
        assert!(parse_memo(&args).is_err());
    }

    #[test]
    fn parse_memo_id() {
        let mut args = minimal_args();
        args.memo_id = Some(42);
        let memo = parse_memo(&args).unwrap();
        assert!(matches!(memo, Memo::Id(_)));
    }

    #[tokio::test]
    async fn pay_cli_explicit_fee_surfaces_metadata() {
        let server = mount_pay_build_rpc("333").await;
        let mut args = minimal_args();
        args.source = Some(SOURCE_G.to_owned());
        args.destination = DEST_G.to_owned();
        args.amount = "1 XLM".to_owned();
        args.fee = Some("250".to_owned());
        args.rpc_url = server.uri();

        let built = build_unsigned_envelope(&args)
            .await
            .expect("explicit fee build succeeds");
        assert_eq!(built.fee_selection.per_op_stroops, 250);
        assert_eq!(built.fee_selection.selected_fee_percentile, "explicit");
        assert_eq!(tx_fee_from_envelope_xdr(&built.envelope_xdr), 250);

        let result = PayResult {
            envelope_xdr: built.envelope_xdr,
            tx_hash: None,
            ledger: None,
            stage: "build".to_owned(),
            selected_fee_per_op_stroops: Some(built.fee_selection.per_op_stroops),
            selected_fee_percentile: Some(built.fee_selection.selected_fee_percentile),
        };
        let json = serde_json::to_value(result).expect("PayResult serialises");
        assert_eq!(json["selected_fee_per_op_stroops"], "250");
        assert_eq!(json["selected_fee_percentile"], "explicit");
    }

    #[test]
    fn pay_result_selected_fee_per_op_stroops_none_round_trips() {
        // The `with = "...::u32_opt"` custom deserializer suppresses serde's
        // implicit missing-field-means-None for `Option<T>`; `#[serde(default)]`
        // restores it. Without it, deserializing this None-produced,
        // field-omitted JSON would fail with "missing field
        // `selected_fee_per_op_stroops`".
        let result = PayResult {
            envelope_xdr: "AAAA".to_owned(),
            tx_hash: None,
            ledger: None,
            stage: "build".to_owned(),
            selected_fee_per_op_stroops: None,
            selected_fee_percentile: None,
        };
        let json = serde_json::to_value(&result).expect("PayResult serialises");
        assert!(json.get("selected_fee_per_op_stroops").is_none());

        let round_tripped: PayResult = serde_json::from_value(json)
            .expect("omitted selected_fee_per_op_stroops must deserialize back to None");
        assert_eq!(round_tripped.selected_fee_per_op_stroops, None);
    }

    #[tokio::test]
    async fn pay_cli_default_fee_surfaces_profile_default() {
        let server = mount_pay_build_rpc("333").await;
        let mut args = minimal_args();
        args.source = Some(SOURCE_G.to_owned());
        args.destination = DEST_G.to_owned();
        args.amount = "1 XLM".to_owned();
        args.rpc_url = server.uri();

        let built = build_unsigned_envelope(&args)
            .await
            .expect("default fee build succeeds");
        assert_eq!(built.fee_selection.per_op_stroops, DEFAULT_FEE_STROOPS);
        assert_eq!(
            built.fee_selection.selected_fee_percentile,
            "profile_default"
        );
    }

    #[tokio::test]
    async fn pay_cli_auto_fee_surfaces_p95() {
        let server = mount_pay_build_rpc("333").await;
        let mut args = minimal_args();
        args.source = Some(SOURCE_G.to_owned());
        args.destination = DEST_G.to_owned();
        args.amount = "1 XLM".to_owned();
        args.fee = Some("auto".to_owned());
        args.rpc_url = server.uri();

        let built = build_unsigned_envelope(&args)
            .await
            .expect("auto fee build succeeds");
        assert_eq!(built.fee_selection.per_op_stroops, 333);
        assert_eq!(built.fee_selection.selected_fee_percentile, "p95");
        assert_eq!(tx_fee_from_envelope_xdr(&built.envelope_xdr), 333);
    }

    /// Constructs a minimal `PayArgs` with default values for fields not under test.
    fn minimal_args() -> PayArgs {
        PayArgs {
            destination: "GABC".to_owned(),
            amount: "10 XLM".to_owned(),
            asset: "native".to_owned(),
            memo_text: None,
            memo_id: None,
            memo_hash_hex: None,
            memo_return_hex: None,
            fee: None,
            source: None,
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
            use_oz_relayer: false,
        }
    }

    // ── --use-oz-relayer opt-in gate ──────────────────────────────────────────

    /// `--use-oz-relayer` parses into `PayArgs.use_oz_relayer == true`.
    #[test]
    fn clap_use_oz_relayer_flag_parses_true() {
        let mut args = base_args();
        args.push("--use-oz-relayer");
        let parsed = try_parse_pay(&args).expect("--use-oz-relayer must parse");
        assert!(parsed.use_oz_relayer, "use_oz_relayer must be true");
    }

    /// Absent `--use-oz-relayer` defaults to `false`.
    #[test]
    fn clap_use_oz_relayer_flag_absent_defaults_false() {
        let args = base_args();
        let parsed = try_parse_pay(&args).expect("base args must parse");
        assert!(
            !parsed.use_oz_relayer,
            "use_oz_relayer must default to false"
        );
    }

    /// `--use-oz-relayer` is NOT mutually exclusive with `--secret-env` or
    /// `--build-only`; it parses successfully alongside them.
    #[test]
    fn clap_use_oz_relayer_not_exclusive_with_signer_flags() {
        let mut args = base_args();
        args.extend(["--use-oz-relayer", "--secret-env", "MY_KEY"]);
        let parsed = try_parse_pay(&args).expect("--use-oz-relayer + --secret-env must parse");
        assert!(parsed.use_oz_relayer);
        assert_eq!(parsed.secret_env.as_deref(), Some("MY_KEY"));
    }

    /// `--use-oz-relayer` is NOT mutually exclusive with `--build-only`.
    #[test]
    fn clap_use_oz_relayer_not_exclusive_with_build_only() {
        let mut args = base_args();
        args.extend(["--use-oz-relayer", "--build-only"]);
        let parsed = try_parse_pay(&args).expect("--use-oz-relayer + --build-only must parse");
        assert!(parsed.use_oz_relayer);
        assert!(parsed.build_only);
    }

    /// When `use_oz_relayer` is set, `check_relayer_opt_in` returns the typed
    /// refuse error without loading any secret or performing any network call.
    #[test]
    fn check_relayer_opt_in_returns_relayer_not_implemented_when_set() {
        let mut args = minimal_args();
        args.use_oz_relayer = true;
        let result = check_relayer_opt_in(&args);
        assert!(
            result.is_err(),
            "must return Err when use_oz_relayer is true"
        );
        let err = result.unwrap_err();
        assert_eq!(
            err.code(),
            "validation.relayer_not_implemented",
            "wire code must be 'validation.relayer_not_implemented'"
        );
        assert!(
            matches!(
                err,
                WalletError::Validation(ValidationError::RelayerNotImplemented)
            ),
            "must be WalletError::Validation(ValidationError::RelayerNotImplemented)"
        );
    }

    /// When `use_oz_relayer` is `false`, `check_relayer_opt_in` returns `Ok(())`.
    #[test]
    fn check_relayer_opt_in_returns_ok_when_not_set() {
        let args = minimal_args();
        assert!(
            check_relayer_opt_in(&args).is_ok(),
            "must return Ok when use_oz_relayer is false"
        );
    }

    /// The `run()` path with `use_oz_relayer = true` returns exit code 1 and
    /// does NOT perform any network call (non-routable RPC address ensures any
    /// accidental call would fail with a connection error rather than silently
    /// succeeding).  The refuse gate is wired before any stage dispatch.
    #[tokio::test]
    async fn relayer_opt_in_exits_nonzero_without_network_call() {
        let mut args = minimal_args();
        args.use_oz_relayer = true;
        // Non-routable address: any accidental RPC call would produce a
        // connection error, making an accidentally-passing test impossible.
        args.rpc_url = "http://127.0.0.1:1".to_owned();
        let exit = run(&args).await;
        assert_eq!(exit, 1, "relayer opt-in must exit with code 1");
    }

    /// The AGPL-3.0 disclosure constant contains the required claims that
    /// must be preserved by any future wording update.
    #[test]
    fn relayer_disclosure_constant_contains_required_claims() {
        assert!(
            RELAYER_AGPL_DISCLOSURE.contains("AGPL-3.0"),
            "disclosure must mention AGPL-3.0"
        );
        assert!(
            RELAYER_AGPL_DISCLOSURE.contains("WOULD subject"),
            "disclosure must use conditional phrasing 'WOULD subject'"
        );
        assert!(
            RELAYER_AGPL_DISCLOSURE.contains("links no AGPL code"),
            "legally load-bearing claim 'links no AGPL code' must be present verbatim"
        );
        assert!(
            RELAYER_AGPL_DISCLOSURE.contains("not implemented in this build"),
            "disclosure must state relayer is not implemented in this build"
        );
    }
}
