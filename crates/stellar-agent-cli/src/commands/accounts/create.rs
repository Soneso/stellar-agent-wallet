//! `stellar-agent accounts create` subcommand — account creation.
//!
//! Creates a new Stellar account on-chain in one of two mutually-exclusive
//! modes:
//!
//! ## Mode A — sponsored `CreateAccount`
//!
//! Required flags: `--sponsor <G-strkey>`, a signer source
//! (`--secret-env <VAR>` or `--sign-with-ledger`), and
//! `--starting-balance <amount>`.
//!
//! The new account public key is supplied as a positional `<new-G-strkey>`
//! argument OR generated in-process with `--generate`. The sponsor's public
//! key must match the signer-derived public key (same guard as the `pay`
//! command). Submits a `CreateAccount` op via `ClassicOpBuilder` and the
//! sign + submit pipeline.
//!
//! ## Mode B — Friendbot
//!
//! Required flag: `--fund-with-friendbot`. The new account public key is
//! supplied as a positional argument or generated with `--generate`.
//! Structurally refused on mainnet at two layers:
//!
//! 1. CLI enum: `TargetNetwork::Mainnet` returns
//!    `network.friendbot_mainnet_forbidden` before any HTTP call.
//! 2. Network layer: `fund_with_friendbot` rejects mainnet passphrases.
//!
//! ## Keypair generation (`--generate`)
//!
//! When `--generate` is present, a fresh ed25519 keypair is generated
//! in-process using `SigningKey::generate(&mut OsRng)`. Both the G-strkey
//! (public) and S-strkey (secret) are included in the output envelope's
//! `data.secret_key` field. The S-strkey is NEVER emitted in table-mode
//! output or in any `tracing` event.
//!
//! ## Mutual exclusivity
//!
//! - `--fund-with-friendbot` and `--sponsor` are mutually exclusive
//!   (verified at argument-group level by clap).
//! - `--generate` and the positional `<new-G-strkey>` are mutually exclusive.
//! - Providing neither mode is a missing-required-group parse error.
//!
//! # mlock-protected signing window
//!
//! The `--secret-env` sponsored-mode path routes through the shared
//! `resolve_software_signer_from_env` ceremony (`Wallet::unlock` →
//! `LockedSeed` mlock-protected page → `signer_from_wallet` → dispose) →
//! `attach_signature` → drop. The `--sign-with-ledger` path uses
//! `signer_from_ledger` (hardware signer; no seed ever held in process memory).
//!
//! # Behavior
//!
//! - All RPC calls go through Stellar RPC.
//! - Ledger signing is available via `--sign-with-ledger`.
//! - The `--secret-env` path holds the seed only inside an mlock-protected
//!   signing window.

use std::time::Duration;

use clap::{ArgGroup, Args};
use rand_core::OsRng;
use stellar_agent_core::StellarAmount;
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{AuthError, NetworkError, ValidationError, WalletError};
use zeroize::Zeroizing;

use stellar_agent_network::builder::ClassicOpBuilder;
use stellar_agent_network::signing::Signer;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::signing::source::signer_from_ledger;
use stellar_agent_network::{
    ClassicFeeSelection, StellarRpcClient, SubmissionResult, SubmissionSignerKind,
    parse_classic_fee_choice, resolve_classic_fee_selection, submit_transaction_and_wait,
};
use stellar_agent_network::{FriendbotResult, fund_with_friendbot};

use crate::common::network::TargetNetwork;
use crate::common::render::{render_json, sanitize_for_table};
use crate::common::signer_ceremony::{SignerCeremonyOutcome, resolve_software_signer_from_env};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default fee per operation in stroops.
const DEFAULT_FEE_STROOPS: u32 = 100;

/// Default submission timeout in seconds.
const DEFAULT_TIMEOUT_SECONDS: u64 = 60;

/// Stellar testnet RPC endpoint (SDF operated).
const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";

/// Default Friendbot URL for testnet (SDF operated).
const DEFAULT_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";

// ─────────────────────────────────────────────────────────────────────────────
// CreateMode — typed mode discriminant (replaces mode: String)
// ─────────────────────────────────────────────────────────────────────────────

/// Discriminant for the account-creation mode used in [`CreateAccountResult`].
///
/// Serialises to `"sponsored"` / `"friendbot"` (lowercase). Round-trip tests
/// verify the serialised form.
///
/// `#[non_exhaustive]` is applied because future modes may be added
/// (e.g. `multisig`, `passkey`). The `print_success` match arm covers the
/// `_` arm for forward-compat with an explicit `render_json` fallback and a
/// comment explaining why.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CreateMode {
    /// Account created via a sponsored `CreateAccount` operation.
    Sponsored,
    /// Account funded via the Stellar Friendbot HTTP endpoint.
    Friendbot,
}

// ─────────────────────────────────────────────────────────────────────────────
// CreateAccountResult — the structured success payload
// ─────────────────────────────────────────────────────────────────────────────

/// Structured payload returned in the JSON envelope on a successful account
/// creation.
///
/// # Secret-key discipline
///
/// `secret_key` is populated only when `--generate` is used. It is captured
/// by the caller from the JSON output; it is **never** emitted in table-mode
/// output and **never** passed through any `tracing` event. The operator is
/// responsible for storing the S-strkey securely after capturing it from the
/// JSON envelope.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CreateAccountResult {
    /// The new account's G-strkey.
    pub account_id: String,

    /// The generated S-strkey for the new account.
    ///
    /// Populated only when `--generate` is passed; `None` when the caller
    /// supplied a positional `<new-G-strkey>`.
    ///
    /// Captured by the caller; never logged.
    ///
    /// # Capture warning
    ///
    /// This field is the operator's only copy of the newly-generated private
    /// key. On its way to the operator it transits multiple non-zeroised
    /// heap allocations (serde serialisation buffers, the `String` passed
    /// to `println!`, OS stdout buffers). Operational consequences:
    ///
    /// - **Terminal scrollback** retains the S-strkey until cleared.
    /// - **Shell history** captures it if the command was run interactively
    ///   without output redirection.
    /// - **Log aggregators** that ingest stdout keep the secret indefinitely.
    /// - **Core dumps** may capture the serialisation buffers verbatim.
    ///
    /// Recommended capture pattern: pipe the JSON output directly to a
    /// restrictive-permission file or a secret-manager CLI, never interactively.
    /// For example, `umask 077 && stellar-agent accounts create --generate ... >
    /// secret.json` places the output under the caller's umask without
    /// touching shell history.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<String>,

    /// Which mode produced this result.
    pub mode: CreateMode,

    /// Transaction hash (64-character hex), present after sponsored
    /// submission or from the Friendbot response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,

    /// Confirmed ledger sequence number (sponsored mode only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ledger: Option<u32>,

    /// The Friendbot endpoint URL that was called (friendbot mode only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub friendbot_url_used: Option<String>,

    /// Selected per-operation fee in stroops for sponsored mode.
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

    /// Fee selection source for sponsored mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_fee_percentile: Option<String>,
}

#[derive(Debug, Clone)]
struct BuiltCreateAccountEnvelope {
    envelope_xdr: String,
    fee_selection: ClassicFeeSelection,
}

#[derive(Debug, Clone)]
struct SponsoredCreateResult {
    submission: SubmissionResult,
    fee_selection: ClassicFeeSelection,
}

// ─────────────────────────────────────────────────────────────────────────────
// CreateArgs
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `accounts create` subcommand.
///
/// Two mutually-exclusive mode groups:
/// - **sponsored**: `--sponsor` + (`--secret-env` | `--sign-with-ledger`) +
///   `--starting-balance`. Positional `<new-G-strkey>` or `--generate`.
/// - **friendbot**: `--fund-with-friendbot`. Positional `<new-G-strkey>` or
///   `--generate`.
///
/// The `mode_group` ArgGroup enforces that at least one mode flag is present
/// and that the two modes are mutually exclusive. The `account_group` enforces
/// that exactly one of positional `<new-G-strkey>` or `--generate` is used.
#[non_exhaustive]
#[derive(Debug, Args)]
#[command(
    group(
        ArgGroup::new("mode_group")
            .args(["sponsor", "fund_with_friendbot"])
            .required(true)
    ),
    group(
        ArgGroup::new("account_group")
            .args(["new_account", "generate"])
            .required(true)
    ),
    group(
        ArgGroup::new("signer_group")
            .args(["secret_env", "sign_with_ledger"])
            .required(false)
    ),
)]
pub struct CreateArgs {
    /// New account G-strkey. Mutually exclusive with `--generate`.
    #[arg(value_name = "NEW_G_STRKEY", group = "account_group")]
    pub new_account: Option<String>,

    /// Generate a fresh ed25519 keypair in-process.
    ///
    /// Returns both the G-strkey and S-strkey in the JSON envelope.
    /// Mutually exclusive with the positional `<new-G-strkey>` argument.
    #[arg(long, group = "account_group")]
    pub generate: bool,

    /// Starting balance for the new account (e.g. `"5 XLM"`).
    ///
    /// Required for sponsored mode. Bare numeric inputs are rejected; units
    /// are mandatory.
    #[arg(long, value_name = "AMOUNT")]
    pub starting_balance: Option<String>,

    /// Sponsor G-strkey — source account for the `CreateAccount` op.
    ///
    /// Required for sponsored mode. Mutually exclusive with
    /// `--fund-with-friendbot`.
    #[arg(long, value_name = "G_STRKEY", group = "mode_group")]
    pub sponsor: Option<String>,

    /// Name of the environment variable holding the sponsor's S-strkey.
    ///
    /// The value is never logged.
    #[arg(long, value_name = "VAR", group = "signer_group")]
    pub secret_env: Option<String>,

    /// Sign using the connected Ledger hardware wallet.
    #[arg(long, group = "signer_group")]
    pub sign_with_ledger: bool,

    /// Ledger BIP-32 account index (default 0).
    #[arg(long, default_value_t = 0_u32, value_name = "INDEX")]
    pub account_index: u32,

    /// Fund using the Stellar Friendbot HTTP endpoint.
    ///
    /// Testnet only. Structurally refused on mainnet.
    /// Mutually exclusive with `--sponsor`.
    #[arg(long, group = "mode_group")]
    pub fund_with_friendbot: bool,

    /// Network to target. Only `testnet` is accepted.
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Friendbot endpoint URL.
    #[arg(
        long,
        default_value = DEFAULT_FRIENDBOT_URL,
        value_name = "URL"
    )]
    pub friendbot_url: String,

    /// Classic fee per operation for sponsored mode: `<stroops>`, `auto`, or `auto:pNN`.
    #[arg(long, value_name = "STROOPS|auto[:pNN]")]
    pub fee: Option<String>,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,

    /// Submission timeout in seconds (sponsored mode). Default: 60.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,

    /// Override the Stellar RPC endpoint URL (sponsored mode).
    #[arg(
        long,
        default_value = TESTNET_RPC_URL,
        value_name = "URL"
    )]
    pub rpc_url: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// run — main dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Runs the `accounts create` subcommand.
///
/// Dispatches to sponsored mode or Friendbot mode based on the provided flags,
/// then renders the result per `args.output`.
///
/// Returns an exit code: `0` on success, `1` on any error.
///
/// # Errors
///
/// Never returns `Err` — all errors are captured into the envelope.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &CreateArgs) -> i32 {
    if args.fund_with_friendbot {
        run_friendbot(args).await
    } else {
        run_sponsored(args).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Keypair resolution
// ─────────────────────────────────────────────────────────────────────────────

/// The resolved new-account identity: G-strkey plus an optional S-strkey.
///
/// `secret` is `Some` only when `--generate` was passed. It is handled as a
/// `Zeroizing<String>` so the heap allocation is cleared when this struct
/// drops.
///
/// Implements `Debug` via `Zeroizing<String>`'s redacting `Debug` impl
/// (prints `"[REDACTED]"` for the secret content) — safe to use in
/// `assert!` / `unwrap_err` contexts without leaking secret bytes.
#[derive(Debug)]
struct NewAccount {
    /// G-strkey of the new account.
    pub g_strkey: String,
    /// S-strkey — present only when generated in-process.
    ///
    /// Captured by the caller; never logged.
    pub secret: Option<Zeroizing<String>>,
}

/// Resolves or generates the new account keypair.
///
/// When `--generate` is set, generates a fresh ed25519 keypair using
/// `OsRng`. Otherwise, parses and validates the positional G-strkey.
///
/// # Errors
///
/// Returns [`WalletError::Validation`] wrapping [`ValidationError::AddressInvalid`]
/// if the positional argument is not a valid G-strkey.
fn resolve_new_account(args: &CreateArgs) -> Result<NewAccount, WalletError> {
    if args.generate {
        // Generate a fresh ed25519 keypair in-process.
        // `SigningKey` is `ZeroizeOnDrop` via ed25519-dalek's `zeroize` feature.
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let g_strkey = stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
            .to_string()
            .to_string();

        // Seed-to-strkey zeroisation — mirrors the pay.rs pattern.
        // stellar-strkey 0.0.16's `PrivateKey` is `Copy` with no `Drop`/
        // `Zeroize` impl. Wrap the seed in `Zeroizing` so the stack copy is
        // cleared on drop; copy into `PrivateKey`; stringify inside
        // `Zeroizing`; then explicitly zeroise the `PrivateKey.0` Copy residue
        // before it falls out of scope.
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(signing_key.to_bytes());
        let mut private_key = stellar_strkey::ed25519::PrivateKey(*seed);
        let s_strkey: Zeroizing<String> =
            Zeroizing::new(private_key.as_unredacted().to_string().as_str().to_owned());
        zeroize::Zeroize::zeroize(&mut private_key.0);
        // signing_key drops here via ZeroizeOnDrop.
        drop(signing_key);

        Ok(NewAccount {
            g_strkey,
            secret: Some(s_strkey),
        })
    } else {
        // Positional arg — validate it is a G-strkey.
        let addr = args.new_account.as_deref().unwrap_or(""); // clap enforces account_group required; empty is unreachable.

        stellar_strkey::ed25519::PublicKey::from_string(addr).map_err(|_| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: addr.to_owned(),
            })
        })?;

        Ok(NewAccount {
            g_strkey: addr.to_owned(),
            secret: None,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Friendbot mode
// ─────────────────────────────────────────────────────────────────────────────

async fn run_friendbot(args: &CreateArgs) -> i32 {
    // First layer: structural mainnet rejection.
    if args.network == TargetNetwork::Mainnet {
        let err = WalletError::Network(NetworkError::FriendbotMainnetForbidden);
        let envelope = Envelope::<()>::err(&err);
        print_error(&envelope, args.output);
        return 1;
    }

    let new_account = match resolve_new_account(args) {
        Ok(a) => a,
        Err(e) => {
            let envelope = Envelope::<()>::err(&e);
            print_error(&envelope, args.output);
            return 1;
        }
    };

    let passphrase = args.network.passphrase();

    // Second layer: fund_with_friendbot rejects mainnet passphrase.
    match fund_with_friendbot(&args.friendbot_url, &new_account.g_strkey, passphrase).await {
        Ok(fb_result) => {
            let result = build_friendbot_result(&new_account, &fb_result);
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

fn build_friendbot_result(new_account: &NewAccount, fb: &FriendbotResult) -> CreateAccountResult {
    // secret_key: clone out of Zeroizing<String> only for JSON output.
    // The cloned String value is stored in the envelope; the Zeroizing
    // wrapper on `new_account.secret` continues to hold its copy and
    // zeroes it on drop when the NewAccount goes out of scope.
    let secret_key = new_account.secret.as_ref().map(|s| s.as_str().to_owned());

    CreateAccountResult {
        account_id: new_account.g_strkey.clone(),
        secret_key,
        mode: CreateMode::Friendbot,
        tx_hash: Some(fb.tx_hash.clone()),
        ledger: None,
        friendbot_url_used: Some(fb.friendbot_url_used.clone()),
        selected_fee_per_op_stroops: None,
        selected_fee_percentile: None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sponsored mode
// ─────────────────────────────────────────────────────────────────────────────

async fn run_sponsored(args: &CreateArgs) -> i32 {
    // Sponsored mode — mainnet write forbidden.
    if args.network == TargetNetwork::Mainnet {
        let err = WalletError::Network(NetworkError::MainnetWriteForbidden);
        let envelope = Envelope::<()>::err(&err);
        print_error(&envelope, args.output);
        return 1;
    }

    let sponsor = match &args.sponsor {
        Some(s) => s.clone(),
        None => {
            // clap mode_group enforces at least one of sponsor/fund_with_friendbot;
            // reaching this branch is structurally impossible at runtime. Surface as
            // internal state rather than silently doing nothing.
            let err = WalletError::Validation(ValidationError::AddressInvalid {
                input: "--sponsor is required for sponsored mode".to_owned(),
            });
            let envelope = Envelope::<()>::err(&err);
            print_error(&envelope, args.output);
            return 1;
        }
    };

    let starting_balance_str = match &args.starting_balance {
        Some(s) => s.clone(),
        None => {
            let err = WalletError::Validation(ValidationError::AmountMalformed {
                input: "--starting-balance is required for sponsored mode".to_owned(),
            });
            let envelope = Envelope::<()>::err(&err);
            print_error(&envelope, args.output);
            return 1;
        }
    };

    // Boundary discipline: parse_with_unit is the only permitted parser for
    // human-supplied amounts at CLI boundaries.
    let starting_balance = match StellarAmount::parse_with_unit(&starting_balance_str) {
        Ok(a) => a,
        Err(_) => {
            let err = WalletError::Validation(ValidationError::AmountMalformed {
                input: starting_balance_str.clone(),
            });
            let envelope = Envelope::<()>::err(&err);
            print_error(&envelope, args.output);
            return 1;
        }
    };

    let new_account = match resolve_new_account(args) {
        Ok(a) => a,
        Err(e) => {
            let envelope = Envelope::<()>::err(&e);
            print_error(&envelope, args.output);
            return 1;
        }
    };

    // Sign and submit.
    match sponsored_create(args, &sponsor, &new_account.g_strkey, starting_balance).await {
        Ok(sponsored_result) => {
            let secret_key = new_account.secret.as_ref().map(|s| s.as_str().to_owned());
            let sub_result = sponsored_result.submission;

            let result = CreateAccountResult {
                account_id: new_account.g_strkey.clone(),
                secret_key,
                mode: CreateMode::Sponsored,
                tx_hash: Some(sub_result.tx_hash.clone()),
                ledger: Some(sub_result.ledger),
                friendbot_url_used: None,
                selected_fee_per_op_stroops: Some(sponsored_result.fee_selection.per_op_stroops),
                selected_fee_percentile: Some(
                    sponsored_result.fee_selection.selected_fee_percentile,
                ),
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

/// Builds, signs, and submits the `CreateAccount` transaction.
///
/// # Signing path
///
/// - `--sign-with-ledger`: hardware signer; seed never in process memory.
/// - `--secret-env VAR`: mlock-protected signing window. The S-strkey is
///   parsed from the env var, moved into a `Wallet` (LockedSeed), and consumed
///   by `signer_from_wallet`. Both the `SoftwareSigningKey` and the `Wallet`
///   drop after `attach_signature`, triggering SecretBox zeroization and
///   LockedSeed munlock.
///
/// # Errors
///
/// Propagates errors from account fetch, signing, or submission.
async fn sponsored_create(
    args: &CreateArgs,
    sponsor: &str,
    new_account: &str,
    starting_balance: StellarAmount,
) -> Result<SponsoredCreateResult, WalletError> {
    let built =
        build_sponsored_unsigned_envelope(args, sponsor, new_account, starting_balance).await?;

    let passphrase = args.network.passphrase();

    let signed_xdr = if args.sign_with_ledger {
        // Hardware path: seed never enters process memory.
        let signer = signer_from_ledger(args.account_index, sponsor).await?;
        attach_signature(&built.envelope_xdr, &signer, passphrase).await?
    } else if let Some(ref var_name) = args.secret_env {
        // mlock-protected signing window (shared ceremony):
        //
        // 1. Derive the SoftwareSigningKey via
        //    `resolve_software_signer_from_env` (env -> Zeroizing<String> ->
        //    seed Zeroizing<[u8; 32]> -> zeroize PrivateKey.0 residue ->
        //    Wallet::unlock -> signer_from_wallet -> wallet.dispose()).
        // 2. Verify the derived public key matches --sponsor before signing.
        // 3. attach_signature exactly once.
        // 4. Drop SoftwareSigningKey -> SecretBox zeroised.
        //
        // `accounts create` has no audit-writer infrastructure (no
        // `--profile` flag): a degraded unlock is surfaced only via
        // `Wallet::unlock`'s own `tracing::warn!`.
        let SignerCeremonyOutcome {
            signer,
            mlock_degradation: _,
        } = resolve_software_signer_from_env(var_name, "create-account-commit", None).await?;

        // Public-key verification before signing.
        let signer_pk = signer.public_key().await?;
        let signer_gstrkey = signer_pk.to_string().to_string();
        if signer_gstrkey != sponsor {
            return Err(WalletError::Auth(AuthError::SignerKeyMismatch {
                expected: sponsor.to_owned(),
                got: signer_gstrkey,
            }));
        }

        let signed = attach_signature(&built.envelope_xdr, &signer, passphrase).await?;
        drop(signer);
        signed
    } else {
        return Err(WalletError::Auth(AuthError::KeyringLocked));
    };

    // Submit and wait for confirmation.
    let client = StellarRpcClient::new(&args.rpc_url)?;
    let timeout = Duration::from_secs(args.timeout_seconds);
    let submission = submit_transaction_and_wait(
        &client,
        &signed_xdr,
        timeout,
        passphrase,
        Some(SubmissionSignerKind::Software),
    )
    .await?;

    Ok(SponsoredCreateResult {
        submission,
        fee_selection: built.fee_selection,
    })
}

async fn build_sponsored_unsigned_envelope(
    args: &CreateArgs,
    sponsor: &str,
    new_account: &str,
    starting_balance: StellarAmount,
) -> Result<BuiltCreateAccountEnvelope, WalletError> {
    let client = StellarRpcClient::new(&args.rpc_url)?;
    let fee_choice = parse_classic_fee_choice(args.fee.as_deref())?;
    let fee_selection =
        resolve_classic_fee_selection(&client, DEFAULT_FEE_STROOPS, fee_choice).await?;

    // Fetch sponsor account for sequence number.
    // Pass empty slice: account creation only needs the sponsor's sequence number.
    let sponsor_account = stellar_agent_network::fetch_account(&client, sponsor, &[]).await?;
    // Pass the current on-chain sequence directly; `stellar_baselib::TransactionBuilder::build`
    // calls `Account::increment_sequence_number` internally. An explicit +1
    // here would produce CURRENT+2 → TxBadSeq.
    let sequence_number = sponsor_account.sequence_number;

    let passphrase = args.network.passphrase();

    // Build the unsigned CreateAccount transaction.
    let mut builder = ClassicOpBuilder::new(
        sponsor,
        sequence_number,
        passphrase,
        fee_selection.per_op_stroops,
    );
    builder.create_account(new_account, starting_balance)?;

    let envelope_xdr = builder.build()?;

    Ok(BuiltCreateAccountEnvelope {
        envelope_xdr,
        fee_selection,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Output helpers
// ─────────────────────────────────────────────────────────────────────────────

fn print_success(envelope: &Envelope<CreateAccountResult>, format: OutputFormat) {
    match format {
        OutputFormat::Table => {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            if let Some(result) = &envelope.data {
                match &result.mode {
                    CreateMode::Sponsored => {
                        use stellar_agent_network::submit::redact_tx_hash;
                        let hash = result
                            .tx_hash
                            .as_deref()
                            .map(redact_tx_hash)
                            .unwrap_or_default();
                        let ledger = result.ledger.unwrap_or_default();
                        let selected_fee = crate::render::table::render_selected_fee_line(
                            result.selected_fee_per_op_stroops,
                            result.selected_fee_percentile.as_deref(),
                        );
                        println!(
                            "Account created (sponsored): {}  tx_hash {}  ledger {}\n{}",
                            result.account_id, hash, ledger, selected_fee
                        );
                    }
                    CreateMode::Friendbot => {
                        use stellar_agent_network::submit::redact_tx_hash;
                        let hash = result
                            .tx_hash
                            .as_deref()
                            .map(redact_tx_hash)
                            .unwrap_or_default();
                        println!(
                            "Account created (friendbot): {}  tx_hash {}",
                            result.account_id, hash
                        );
                        // secret_key is NEVER emitted in table mode.
                    } // `CreateMode` is `#[non_exhaustive]` but defined same-crate;
                      // the compiler enforces exhaustiveness here without a `_` arm.
                      // A future variant added in this crate forces an explicit
                      // table-arm decision rather than silently falling through to
                      // JSON.
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
        reason = "test-only; panics and unwraps are acceptable in unit tests"
    )]

    use std::sync::Arc;

    use super::*;
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers::method};

    const SOURCE_G: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
    const DEST_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

    struct CreateBuildRpcResponder {
        account_key_xdr: String,
        account_xdr: String,
        fee_stats: Arc<serde_json::Value>,
    }

    impl CreateBuildRpcResponder {
        fn new(account_key_xdr: String, account_xdr: String, fee_stats: serde_json::Value) -> Self {
            Self {
                account_key_xdr,
                account_xdr,
                fee_stats: Arc::new(fee_stats),
            }
        }
    }

    #[async_trait::async_trait]
    impl Respond for CreateBuildRpcResponder {
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

    async fn mount_create_build_rpc(p95: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(CreateBuildRpcResponder::new(
                account_ledger_key_xdr(SOURCE_G),
                account_entry_xdr_with_balance(SOURCE_G, 100_000_000_000),
                fee_stats_result(p95, "999"),
            ))
            .mount(&server)
            .await;
        server
    }

    // ── Clap mutex tests ─────────────────────────────────────────────────────

    /// Parses `CreateArgs` from a vec of string slices via the Command interface.
    fn try_parse_create(args: &[&str]) -> Result<CreateArgs, clap::Error> {
        use clap::Parser;

        #[derive(Debug, clap::Parser)]
        struct TestCreate {
            #[command(flatten)]
            args: CreateArgs,
        }

        TestCreate::try_parse_from(args).map(|t| t.args)
    }

    /// Helper: a minimal valid friendbot invocation arg list.
    fn friendbot_args() -> Vec<&'static str> {
        vec![
            "create",
            "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            "--fund-with-friendbot",
        ]
    }

    /// Helper: a minimal valid sponsored invocation arg list.
    fn sponsored_args() -> Vec<&'static str> {
        vec![
            "create",
            "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            "--sponsor",
            "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
            "--secret-env",
            "SPONSOR_SECRET",
            "--starting-balance",
            "5 XLM",
        ]
    }

    #[test]
    fn friendbot_and_sponsor_are_mutually_exclusive() {
        let mut args = friendbot_args();
        args.extend([
            "--sponsor",
            "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
        ]);
        let result = try_parse_create(&args);
        assert!(
            result.is_err(),
            "--fund-with-friendbot + --sponsor must conflict"
        );
        assert_eq!(
            result.unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn generate_and_positional_are_mutually_exclusive() {
        let args = vec![
            "create",
            "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            "--generate",
            "--fund-with-friendbot",
        ];
        let result = try_parse_create(&args);
        assert!(result.is_err(), "positional + --generate must conflict");
        assert_eq!(
            result.unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn no_mode_flag_is_rejected() {
        // Neither --fund-with-friendbot nor --sponsor → clap missing-required-group.
        let args = vec![
            "create",
            "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
        ];
        let result = try_parse_create(&args);
        assert!(result.is_err(), "no mode flag must be rejected");
    }

    #[test]
    fn no_account_flag_is_rejected() {
        // Neither positional nor --generate → missing account_group.
        let args = vec!["create", "--fund-with-friendbot"];
        let result = try_parse_create(&args);
        assert!(result.is_err(), "no account source must be rejected");
    }

    #[test]
    fn secret_env_and_sign_with_ledger_are_mutually_exclusive() {
        let mut args = sponsored_args();
        args.push("--sign-with-ledger");
        let result = try_parse_create(&args);
        assert!(
            result.is_err(),
            "--secret-env + --sign-with-ledger must conflict"
        );
        assert_eq!(
            result.unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn friendbot_args_parse_successfully() {
        let args = friendbot_args();
        let parsed = try_parse_create(&args).expect("friendbot args must parse");
        assert!(parsed.fund_with_friendbot);
        assert_eq!(
            parsed.new_account.as_deref(),
            Some("GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL")
        );
    }

    #[test]
    fn sponsored_args_parse_successfully() {
        let args = sponsored_args();
        let parsed = try_parse_create(&args).expect("sponsored args must parse");
        assert_eq!(
            parsed.sponsor.as_deref(),
            Some("GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY")
        );
        assert_eq!(parsed.secret_env.as_deref(), Some("SPONSOR_SECRET"));
        assert_eq!(parsed.starting_balance.as_deref(), Some("5 XLM"));
    }

    // ── Network / mainnet rejection tests ────────────────────────────────────

    #[tokio::test]
    async fn friendbot_mainnet_rejected_before_http_call() {
        let args = CreateArgs {
            new_account: Some(
                "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL".to_owned(),
            ),
            generate: false,
            starting_balance: None,
            sponsor: None,
            secret_env: None,
            sign_with_ledger: false,
            account_index: 0,
            fund_with_friendbot: true,
            network: TargetNetwork::Mainnet,
            // Non-routable: if any HTTP call were made it would fail with a
            // connection error, making an accidentally-passing test impossible.
            friendbot_url: "http://127.0.0.1:1".to_owned(),
            output: OutputFormat::Json,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            rpc_url: "http://127.0.0.1:1".to_owned(),
            fee: None,
        };
        let exit = run(&args).await;
        assert_eq!(exit, 1, "mainnet friendbot must exit with code 1");
    }

    #[tokio::test]
    async fn sponsored_mainnet_rejected_before_rpc_call() {
        let args = CreateArgs {
            new_account: Some(
                "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL".to_owned(),
            ),
            generate: false,
            starting_balance: Some("5 XLM".to_owned()),
            sponsor: Some("GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".to_owned()),
            secret_env: Some("SPONSOR_SECRET".to_owned()),
            sign_with_ledger: false,
            account_index: 0,
            fund_with_friendbot: false,
            network: TargetNetwork::Mainnet,
            friendbot_url: "http://127.0.0.1:1".to_owned(),
            output: OutputFormat::Json,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            rpc_url: "http://127.0.0.1:1".to_owned(),
            fee: None,
        };
        let exit = run(&args).await;
        assert_eq!(exit, 1, "mainnet sponsored must exit with code 1");
    }

    #[tokio::test]
    async fn accounts_create_cli_explicit_fee_surfaces_metadata() {
        let server = mount_create_build_rpc("333").await;
        let mut args = minimal_sponsored_args();
        args.fee = Some("250".to_owned());
        args.rpc_url = server.uri();
        let starting_balance =
            StellarAmount::parse_with_unit("1 XLM").expect("test amount with unit must parse");

        let built = build_sponsored_unsigned_envelope(&args, SOURCE_G, DEST_G, starting_balance)
            .await
            .expect("explicit fee create-account build succeeds");
        assert_eq!(built.fee_selection.per_op_stroops, 250);
        assert_eq!(built.fee_selection.selected_fee_percentile, "explicit");
        assert_eq!(tx_fee_from_envelope_xdr(&built.envelope_xdr), 250);

        let result = CreateAccountResult {
            account_id: DEST_G.to_owned(),
            secret_key: None,
            mode: CreateMode::Sponsored,
            tx_hash: None,
            ledger: None,
            friendbot_url_used: None,
            selected_fee_per_op_stroops: Some(built.fee_selection.per_op_stroops),
            selected_fee_percentile: Some(built.fee_selection.selected_fee_percentile),
        };
        let json = serde_json::to_value(result).expect("CreateAccountResult serialises");
        assert_eq!(json["selected_fee_per_op_stroops"], "250");
        assert_eq!(json["selected_fee_percentile"], "explicit");
    }

    #[test]
    fn create_account_result_selected_fee_per_op_stroops_none_round_trips() {
        // The `with = "...::u32_opt"` custom deserializer suppresses serde's
        // implicit missing-field-means-None for `Option<T>`; `#[serde(default)]`
        // restores it. Without it, deserializing this None-produced,
        // field-omitted JSON would fail with "missing field
        // `selected_fee_per_op_stroops`".
        let result = CreateAccountResult {
            account_id: DEST_G.to_owned(),
            secret_key: None,
            mode: CreateMode::Sponsored,
            tx_hash: None,
            ledger: None,
            friendbot_url_used: None,
            selected_fee_per_op_stroops: None,
            selected_fee_percentile: None,
        };
        let json = serde_json::to_value(&result).expect("CreateAccountResult serialises");
        assert!(json.get("selected_fee_per_op_stroops").is_none());

        let round_tripped: CreateAccountResult = serde_json::from_value(json)
            .expect("omitted selected_fee_per_op_stroops must deserialize back to None");
        assert_eq!(round_tripped.selected_fee_per_op_stroops, None);
    }

    #[tokio::test]
    async fn accounts_create_cli_default_fee_surfaces_profile_default() {
        let server = mount_create_build_rpc("333").await;
        let mut args = minimal_sponsored_args();
        args.rpc_url = server.uri();
        let starting_balance =
            StellarAmount::parse_with_unit("1 XLM").expect("test amount with unit must parse");

        let built = build_sponsored_unsigned_envelope(&args, SOURCE_G, DEST_G, starting_balance)
            .await
            .expect("default fee create-account build succeeds");
        assert_eq!(built.fee_selection.per_op_stroops, DEFAULT_FEE_STROOPS);
        assert_eq!(
            built.fee_selection.selected_fee_percentile,
            "profile_default"
        );
    }

    #[tokio::test]
    async fn accounts_create_cli_auto_fee_surfaces_p95() {
        let server = mount_create_build_rpc("333").await;
        let mut args = minimal_sponsored_args();
        args.fee = Some("auto".to_owned());
        args.rpc_url = server.uri();
        let starting_balance =
            StellarAmount::parse_with_unit("1 XLM").expect("test amount with unit must parse");

        let built = build_sponsored_unsigned_envelope(&args, SOURCE_G, DEST_G, starting_balance)
            .await
            .expect("auto fee create-account build succeeds");
        assert_eq!(built.fee_selection.per_op_stroops, 333);
        assert_eq!(built.fee_selection.selected_fee_percentile, "p95");
        assert_eq!(tx_fee_from_envelope_xdr(&built.envelope_xdr), 333);
    }

    // ── Network FromStr round-trips ──────────────────────────────────────────

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

    // ── Keypair generation ────────────────────────────────────────────────────

    /// `--generate` produces a G/S pair where the secret actually derives the
    /// returned public key.
    ///
    /// This test would fail if `resolve_new_account` returned a mismatched
    /// G/S pair (e.g. generated two independent keypairs and took the public
    /// key from one and the secret from the other).
    #[test]
    fn resolve_new_account_generate_produces_valid_strkeys() {
        let args = CreateArgs {
            new_account: None,
            generate: true,
            starting_balance: None,
            sponsor: None,
            secret_env: None,
            sign_with_ledger: false,
            account_index: 0,
            fund_with_friendbot: true,
            network: TargetNetwork::Testnet,
            friendbot_url: DEFAULT_FRIENDBOT_URL.to_owned(),
            output: OutputFormat::Json,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            rpc_url: TESTNET_RPC_URL.to_owned(),
            fee: None,
        };
        let acc = resolve_new_account(&args).expect("generate must succeed");

        // Decode G-strkey to raw 32-byte public key.
        let pub_key = stellar_strkey::ed25519::PublicKey::from_string(&acc.g_strkey)
            .expect("generated G-strkey must be valid");

        // S-strkey must be present and valid.
        let secret = acc
            .secret
            .expect("secret must be present when --generate is set");
        let priv_key = stellar_strkey::ed25519::PrivateKey::from_string(&secret)
            .expect("generated S-strkey must be valid");

        // Reconstruct the verifying key from the secret seed and confirm it
        // matches the returned G-strkey.  This assertion fails if the returned
        // G/S pair is mismatched (two independent keypairs).
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&priv_key.0);
        assert_eq!(
            signing_key.verifying_key().to_bytes(),
            pub_key.0,
            "secret seed must derive the returned public key"
        );
    }

    #[test]
    fn resolve_new_account_positional_invalid_returns_error() {
        let args = CreateArgs {
            new_account: Some("NOTASTRKEY".to_owned()),
            generate: false,
            starting_balance: None,
            sponsor: None,
            secret_env: None,
            sign_with_ledger: false,
            account_index: 0,
            fund_with_friendbot: true,
            network: TargetNetwork::Testnet,
            friendbot_url: DEFAULT_FRIENDBOT_URL.to_owned(),
            output: OutputFormat::Json,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            rpc_url: TESTNET_RPC_URL.to_owned(),
            fee: None,
        };
        let result = resolve_new_account(&args);
        assert!(result.is_err(), "invalid G-strkey must return an error");
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                WalletError::Validation(ValidationError::AddressInvalid { .. })
            ),
            "expected AddressInvalid, got: {err:?}"
        );
    }

    /// When `--generate` is not set, the `NewAccount.secret` field is `None`,
    /// which causes `CreateAccountResult.secret_key` to be `None`.
    #[test]
    fn secret_key_absent_when_not_generating() {
        let args = CreateArgs {
            new_account: Some(
                "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL".to_owned(),
            ),
            generate: false,
            starting_balance: None,
            sponsor: None,
            secret_env: None,
            sign_with_ledger: false,
            account_index: 0,
            fund_with_friendbot: true,
            network: TargetNetwork::Testnet,
            friendbot_url: DEFAULT_FRIENDBOT_URL.to_owned(),
            output: OutputFormat::Json,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            rpc_url: TESTNET_RPC_URL.to_owned(),
            fee: None,
        };
        let acc = resolve_new_account(&args).expect("positional G-strkey must resolve");
        assert!(
            acc.secret.is_none(),
            "secret must be None when --generate is not set"
        );
    }

    /// When `--generate` is set, the `NewAccount.secret` field is `Some` and
    /// the secret seed derives the returned G-strkey public key.
    ///
    /// This test would fail if `resolve_new_account` returned a mismatched
    /// G/S pair or if the secret field were absent.
    #[test]
    fn secret_key_present_when_generating() {
        let args = CreateArgs {
            new_account: None,
            generate: true,
            starting_balance: None,
            sponsor: None,
            secret_env: None,
            sign_with_ledger: false,
            account_index: 0,
            fund_with_friendbot: true,
            network: TargetNetwork::Testnet,
            friendbot_url: DEFAULT_FRIENDBOT_URL.to_owned(),
            output: OutputFormat::Json,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            rpc_url: TESTNET_RPC_URL.to_owned(),
            fee: None,
        };
        let acc = resolve_new_account(&args).expect("--generate must succeed");
        assert!(
            acc.secret.is_some(),
            "secret must be Some when --generate is set"
        );

        // Decode both strkeys and verify the secret derives the public key.
        let secret = acc.secret.unwrap();
        let priv_key = stellar_strkey::ed25519::PrivateKey::from_string(&secret)
            .expect("generated S-strkey must be valid");
        let pub_key = stellar_strkey::ed25519::PublicKey::from_string(&acc.g_strkey)
            .expect("generated G-strkey must be valid");

        // Reconstruct the verifying key from the secret seed and confirm it
        // matches the returned G-strkey.  This assertion fails if the returned
        // G/S pair is mismatched (two independent keypairs).
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&priv_key.0);
        assert_eq!(
            signing_key.verifying_key().to_bytes(),
            pub_key.0,
            "secret seed must derive the returned public key"
        );
    }

    // ── CreateMode wire-format round-trip ────────────────────────────────────

    /// `CreateMode` must serialise to exactly `"sponsored"` / `"friendbot"`.
    #[test]
    fn create_mode_serialises_to_lowercase_strings() {
        let sponsored = serde_json::to_string(&CreateMode::Sponsored).unwrap();
        let friendbot = serde_json::to_string(&CreateMode::Friendbot).unwrap();
        assert_eq!(sponsored, "\"sponsored\"");
        assert_eq!(friendbot, "\"friendbot\"");
    }

    /// Round-trip: deserialise the lowercase `"sponsored"` / `"friendbot"`
    /// strings back into `CreateMode`.
    #[test]
    fn create_mode_deserialises_from_lowercase_strings() {
        let sponsored: CreateMode = serde_json::from_str("\"sponsored\"").unwrap();
        let friendbot: CreateMode = serde_json::from_str("\"friendbot\"").unwrap();
        assert!(matches!(sponsored, CreateMode::Sponsored));
        assert!(matches!(friendbot, CreateMode::Friendbot));
    }

    #[test]
    fn sanitize_for_table_strips_control_chars() {
        use crate::common::render::sanitize_for_table;
        let input = "hello\x1b[1mworld\x07";
        let sanitized = sanitize_for_table(input);
        assert!(!sanitized.contains('\x1b'), "escape must be stripped");
        assert!(!sanitized.contains('\x07'), "bell must be stripped");
        assert!(sanitized.contains("hello"), "printable chars must survive");
    }

    fn minimal_sponsored_args() -> CreateArgs {
        CreateArgs {
            new_account: Some(DEST_G.to_owned()),
            generate: false,
            starting_balance: Some("1 XLM".to_owned()),
            sponsor: Some(SOURCE_G.to_owned()),
            secret_env: None,
            sign_with_ledger: false,
            account_index: 0,
            fund_with_friendbot: false,
            network: TargetNetwork::Testnet,
            friendbot_url: DEFAULT_FRIENDBOT_URL.to_owned(),
            output: OutputFormat::Json,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            rpc_url: TESTNET_RPC_URL.to_owned(),
            fee: None,
        }
    }
}
