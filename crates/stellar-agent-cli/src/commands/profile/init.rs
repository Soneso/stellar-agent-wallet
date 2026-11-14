//! `stellar-agent profile init` — create and persist a new profile TOML.
//!
//! Docs and the MCP server's first-run guidance reference this command as the
//! way to move past the in-memory testnet fallback (see
//! [`stellar_agent_core::profile::loader::load_default_or_testnet_fallback`]).
//! It mints a version-2 profile with the per-profile-derived keyring entry
//! references [`Profile::builder_testnet_named`] / [`Profile::builder_mainnet_named`]
//! produce, then writes it to `<profile_dir>/<name>.toml`.
//!
//! # Keyring references
//!
//! The signer and nonce coordinates come from
//! [`KeyringEntryRef::default_signer`] / [`KeyringEntryRef::default_nonce`]
//! (`stellar-agent-signer-<name>` / `stellar-agent-nonce-<name>`) — the same
//! derivations `load_default_or_testnet_fallback`'s in-memory fallback
//! profile uses. Both accounts are seeded with the placeholder `"default"` —
//! the signer's eventual G-strkey identity is not known until a seed is
//! enrolled (see "Account-as-identity" in `enroll_signer.rs`'s module
//! documentation for how `enroll-signer` pins it). The five
//! security-substrate references (`audit_log_hash_chain_key_id`,
//! `policy_owner_key_id`, `attestation_key_id`, `counterparty_cache_key_id`,
//! `policy_window_state_key_id`) are derived from the profile name by
//! [`Profile::builder_testnet_named`] / [`Profile::builder_mainnet_named`]. No
//! key material is minted and no audit row is emitted — the key-writing
//! commands (`enroll-signer`, `enroll-owner-key`, the `rotate-*` subcommands)
//! mint their own keys and emit their own `keyring_key_written` rows.
//!
//! # Audit key is required on every engine before signing
//!
//! Because `init` mints the `audit_log_hash_chain_key_id` keyring COORDINATE
//! only (no key material), every value-moving signing verb refuses with
//! `audit.chain_key_unavailable` until `stellar-agent profile rotate-audit-key
//! <name>` mints the key — this applies to the `noop` engine exactly as it
//! does to `v1`, since the audit pre-flight is independent of the policy
//! engine. On both engines, `next_steps` lists `rotate-audit-key` first,
//! then `enroll-signer`, then `rotate-nonce-key` for MCP payment simulation.
//! The audit key must exist before the first key-writing command so its
//! `keyring_key_written` audit row is written.
//!
//! # Engine default
//!
//! `--engine` defaults to `v1`; [`PolicyEngineKind::default`] is `V1`.
//! V1 setup requires an enrolled owner key, an attestation key, and an
//! existing policy file signed with `sign-policy`. The CLI reference's
//! `profile init` entry links the complete setup sequence.
//! A testnet `--engine noop` profile supports server startup and read access
//! immediately. MCP payment simulation requires `rotate-nonce-key`. MCP signing
//! requires `rotate-audit-key` and `enroll-signer` on both engines. The Noop
//! engine allows testnet calls and restricts mainnet to read-only calls.
//! `smart-account multicall` requires `v1` and refuses a Noop profile with
//! `policy.engine_required`.
//!
//! # Endpoint rule
//!
//! Mainnet has no default endpoint, so `init` refuses `--network mainnet`
//! without `--rpc-url`. Testnet does not require the flag: an omitted
//! `--rpc-url` takes the built-in testnet endpoint.
//!
//! The resolved `rpc_url` must pass the endpoint rule the profile loader
//! applies ([`stellar_agent_core::profile::schema::check_endpoint_url`]): an
//! `http` or `https` URL on every chain, and on mainnet an `https` URL with no
//! username or password. `init` therefore never writes a file the loader
//! would refuse.
//!
//! # Fee cap
//!
//! A mainnet profile is written with `classic_max_fee_per_op_stroops = 10000`,
//! because a mainnet classic stage refuses to sign or send without a
//! per-operation fee cap. A testnet profile is written without one.
//!
//! # Mainnet presets
//!
//! On `--network mainnet --engine v1`, `init` also writes the unsigned
//! `version = 2` policy body of a spending preset to
//! `<policy_dir>/<name>.toml`. `--preset` names it (default `api-day`),
//! `--asset` picks USDC or XLM, and XLM takes `--tolerated-loss` and
//! `--typical-payment`. `--unlisted-budget` chooses one budget for
//! unlisted recipients, shared by every payment tool, and `--total-budget`
//! a total for the signed policy's digest: signing the same policy body
//! again keeps that allocation, and a different digest starts another.
//! These flags and `--output`
//! apply to mainnet V1 only.
//!
//! At a terminal (stdin and stderr), `init` asks for a missing XLM amount,
//! for a missing unlisted choice of an api preset, and for a missing total
//! budget choice. Without a terminal the total budget is chosen, and any
//! other missing input refuses with `profile.preset_input_required`.
//!
//! Before any write, `init` writes the spending preview to stderr. It holds
//! the summary of the body, with `authority_status = "draft"`, and the
//! funding plan, as one JSON line or, with `--output table`, a table. The policy
//! file follows, then the profile, then the envelope, whose `data` carries
//! `spending_summary` and `plan`. The policy file is written without
//! replacing a file: an existing file of equal bytes is kept, so a rerun
//! continues, and other content refuses. Every refusal after the preview
//! carries it at `error.details.preview`.
//!
//! # Refusal order
//!
//! The flag parser refuses a malformed `--rpc-url`, and one that carries
//! userinfo, before the command runs: exit code `1` with one
//! `validation.usage_error` envelope on stdout, whose message never repeats
//! the rejected value. After the arguments parse, `init` refuses in this
//! order: an unsafe profile name, mainnet without `--rpc-url`, an existing
//! destination file, and an endpoint that breaks the endpoint rule. Then
//! come a spending flag outside mainnet V1, a refused preset input, a
//! generated body that does not load, an unwritable preview, the policy
//! file, and the profile write.
//!
//! # Overwrite refusal
//!
//! `init` refuses when `<name>.toml` already exists, before building or
//! writing anything, and the write itself goes through
//! [`stellar_agent_core::profile::loader::save_new_to_dir`], whose no-clobber
//! persist repeats the refusal atomically — a file appearing between the
//! check and the write is never overwritten. The existing file is never read
//! or modified by a refused `init`.
//!
//! # Output (JSON envelope)
//!
//! On success:
//!
//! ```json
//! {
//!   "ok": true,
//!   "data": {
//!     "profile": "default",
//!     "path": "/home/user/.local/share/stellar-agent/profiles/default.toml",
//!     "chain_id": "stellar:testnet",
//!     "rpc_url": "https://soroban-testnet.stellar.org",
//!     "engine": "v1",
//!     "next_steps": [
//!       "Run `stellar-agent profile rotate-audit-key default` to mint the audit-log hash-chain key (required before any signing verb will proceed).",
//!       "Run `stellar-agent profile enroll-signer --profile default --secret-env <VAR>` to register the MCP signer seed.",
//!       "Run `stellar-agent profile rotate-nonce-key default` to mint the commit-nonce key (required before MCP payment simulation).",
//!       "Run `stellar-agent profile enroll-owner-key --profile default --secret-env <VAR>` to enroll the policy-file owner key.",
//!       "Run `stellar-agent profile rotate-attestation-key default` to mint the approval-attestation key.",
//!       "Create the V1 policy file `policies/default.toml` in the wallet's state directory, with `version = 1` and `scope = \"profile:default\"` (see \"Create the V1 policy file\" in the getting-started guide).",
//!       "Run `stellar-agent profile sign-policy --profile default --secret-env <VAR>` to sign the V1 policy file."
//!     ]
//!   },
//!   "request_id": "..."
//! }
//! ```
//!
//! # Errors
//!
//! Returns exit code `1`, with these refusals in this order:
//!
//! - `validation.config_invalid` when the profile name is not a safe path
//!   component.
//! - `validation.mainnet_rpc_url_required` when `--network mainnet` is
//!   selected without `--rpc-url`.
//! - `validation.profile_already_exists` when a profile named
//!   `--profile <NAME>` already exists.
//! - `validation.config_invalid` when the resolved `rpc_url` breaks the
//!   endpoint rule.
//! - `validation.usage_error` when a spending flag or `--output` is given
//!   outside `--network mainnet --engine v1`. The message names the flags,
//!   never their values.
//! - `profile.preset_invalid` for an unknown preset, a malformed amount, or
//!   an amount flag on a USDC preset. It also covers `--unlisted-budget yes`
//!   on a preset other than api, a derived limit of zero, and an answer that
//!   is not yes or no.
//! - `profile.preset_input_required` for a missing XLM amount or a missing
//!   unlisted choice of an api preset that no terminal can supply.
//! - `internal.unexpected_state` when the generated policy body does not
//!   load.
//! - `profile.spending_preview_unwritable` when the preview cannot be
//!   written to stderr; nothing is written.
//! - `profile.policy_already_exists` when the policy file holds other
//!   content, and `profile.preset_write_failed` when it cannot be written;
//!   the profile is not written.
//! - `validation.profile_already_exists` when the profile file appears
//!   before the no-clobber write, and an internal error when the profile
//!   write itself fails (I/O error, unwritable directory).

use std::future::Future;
use std::io::{self, Write};
use std::path::Path;

use clap::{Args, ValueEnum};
use serde::Serialize;

use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{InternalError, ValidationError, WalletError};
use stellar_agent_core::policy::v1::presets::{
    self, Archetype, AuthorityStatus, DEFAULT_PRESET, DerivedSpending, PresetAsset, PresetError,
    PresetInput, PresetPlan, SpendingSummary,
};
use stellar_agent_core::policy::v1::validate_unsigned_policy;
use stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE;
use stellar_agent_core::profile::loader;
use stellar_agent_core::profile::schema::{
    KeyringEntryRef, PolicyEngineKind, Profile, default_policy_dir,
};
use stellar_agent_core::redact::redact_url_authority;
use stellar_agent_stablecoin::pins::USDC_MAINNET_ISSUER;

use crate::common::network::{EndpointUrlFlag, TargetNetwork};
use crate::common::spending_preview::{SpendingPreview, with_shown_preview};
use crate::common::tty::{read_line_from_terminal, stdin_and_stderr_are_terminals};
use crate::common::{render, resolve_profile_name, validate_path_component_ascii_safe};

/// The payment asset of a spending preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum PresetAssetArg {
    /// USDC of the mainnet issuer.
    #[value(name = "USDC")]
    Usdc,
    /// Native XLM.
    #[value(name = "XLM")]
    Xlm,
}

impl PresetAssetArg {
    /// The code the prompts name.
    const fn code(self) -> &'static str {
        match self {
            Self::Usdc => "USDC",
            Self::Xlm => "XLM",
        }
    }
}

/// A yes or no choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum YesNo {
    /// Yes.
    Yes,
    /// No.
    No,
}

/// Arguments for `stellar-agent profile init`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub(crate) struct InitArgs {
    /// Name of the profile to create.
    ///
    /// Defaults to the `STELLAR_AGENT_PROFILE` env var, then `"default"`.
    #[arg(long = "profile", value_name = "NAME")]
    pub(crate) profile: Option<String>,

    /// Target network for the new profile.
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub(crate) network: TargetNetwork,

    /// Soroban RPC endpoint for the new profile.
    ///
    /// Optional for testnet (defaults to the built-in testnet endpoint).
    /// Required for `--network mainnet`, which has no default endpoint, and
    /// required there to be an `https://` URL. Every chain accepts only
    /// `http` and `https` URLs. URL credentials are refused.
    #[arg(long, value_name = "URL", value_parser = EndpointUrlFlag)]
    pub(crate) rpc_url: Option<String>,

    /// Policy engine for the new profile.
    #[arg(long, default_value_t = PolicyEngineKind::V1, value_name = "ENGINE")]
    pub(crate) engine: PolicyEngineKind,

    /// Spending preset of the generated mainnet policy body.
    ///
    /// Defaults to `api-day`. Each `-week` preset fits an agent left
    /// unattended for a week. Applies to `--network mainnet --engine v1`
    /// only, as do the six flags after it.
    #[arg(long, value_name = "NAME")]
    pub(crate) preset: Option<String>,

    /// Payment asset of the preset. Defaults to USDC.
    #[arg(long, value_enum, value_name = "USDC|XLM")]
    pub(crate) asset: Option<PresetAssetArg>,

    /// Tolerated loss over the preset's unattended days, in XLM.
    ///
    /// No default: XLM requires it and asks for it at a terminal. A USDC
    /// preset fixes it and refuses the flag.
    #[arg(long, value_name = "AMOUNT")]
    pub(crate) tolerated_loss: Option<String>,

    /// Typical payment, in XLM.
    ///
    /// No default: XLM requires it and asks for it at a terminal. A USDC
    /// preset fixes it and refuses the flag.
    #[arg(long, value_name = "AMOUNT")]
    pub(crate) typical_payment: Option<String>,

    /// Whether the payment tools pay unlisted recipients from one shared
    /// budget; api presets only.
    ///
    /// No default: an api preset asks at a terminal and refuses without
    /// one. Other presets default to no.
    #[arg(long, value_enum, value_name = "yes|no")]
    pub(crate) unlisted_budget: Option<YesNo>,

    /// Whether the payment rules carry a total budget until the next policy
    /// signature.
    ///
    /// Defaults to yes. Without the flag, a terminal asks, with yes as the
    /// default answer.
    #[arg(long, value_enum, value_name = "yes|no")]
    pub(crate) total_budget: Option<YesNo>,

    /// Format of the spending preview on stderr: `json` or `table`.
    ///
    /// Defaults to `json`. The envelope on stdout stays JSON.
    #[arg(long, value_name = "FORMAT")]
    pub(crate) output: Option<OutputFormat>,
}

/// Success payload for the `profile init` envelope.
#[derive(Debug, Serialize)]
struct InitData {
    /// Name of the profile that was created.
    profile: String,
    /// Path the profile TOML was written to.
    path: String,
    /// CAIP-2 chain id (`"stellar:testnet"` or `"stellar:mainnet"`).
    chain_id: String,
    /// Resolved Soroban RPC endpoint as scheme, host, and port only.
    rpc_url: String,
    /// Selected policy engine (`"v1"` or `"noop"`).
    engine: String,
    /// Operator-facing enrollment guidance: the follow-up steps needed
    /// before the profile can sign, in order. See [`next_steps`].
    next_steps: Vec<String>,
    /// The bounds of the generated policy body, on mainnet V1 only.
    #[serde(skip_serializing_if = "Option::is_none")]
    spending_summary: Option<SpendingSummary>,
    /// The funding plan of the preset, on mainnet V1 only.
    #[serde(skip_serializing_if = "Option::is_none")]
    plan: Option<PresetPlan>,
}

/// Runs `stellar-agent profile init`.
///
/// Returns `0` on success, `1` on error.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &InitArgs) -> i32 {
    let profile_dir = match loader::default_profile_dir() {
        Ok(dir) => dir,
        Err(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("could not determine profile directory: {e}"),
            });
            render::render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };
    let policy_dir = match default_policy_dir() {
        Ok(dir) => dir,
        Err(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("could not determine policy directory: {e}"),
            });
            render::render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };
    run_with_dependencies(
        args,
        &profile_dir,
        &policy_dir,
        &mut std::io::stderr(),
        || read_line_from_terminal("profile-init-answer"),
    )
    .await
}

/// First-stage typed refusals, evaluated before any build or write work.
///
/// Pinned by unit tests via the wire codes, in this order:
/// `validation.config_invalid` (unsafe profile name),
/// `validation.mainnet_rpc_url_required` (mainnet without `--rpc-url`), and
/// `validation.profile_already_exists` (destination file present; the
/// no-clobber persist repeats this refusal atomically at write time). The
/// endpoint rule runs after these, in [`build_profile`].
fn init_refusal(args: &InitArgs, profile_name: &str, profile_dir: &Path) -> Option<WalletError> {
    // The name becomes a path component (`<profile_dir>/<name>.toml`);
    // reject path traversal / control characters before any filesystem access.
    //
    // `ConfigInvalid` is the variant whose contract covers profile resolution;
    // `AddressInvalid` is reserved for Stellar account addresses and would
    // render the refusal as an address-parse failure. `profile show` reports
    // the same input class under the same code.
    if let Err(reason) = validate_path_component_ascii_safe(profile_name) {
        return Some(WalletError::Validation(ValidationError::ConfigInvalid {
            component: "profile",
            reason: format!("the profile name is not a valid profile name: {reason}"),
        }));
    }

    if args.network == TargetNetwork::Mainnet && args.rpc_url.is_none() {
        return Some(WalletError::Validation(
            ValidationError::MainnetRpcUrlRequired,
        ));
    }

    let dest = profile_dir.join(format!("{profile_name}.toml"));
    if dest.exists() {
        return Some(WalletError::Validation(
            ValidationError::ProfileAlreadyExists,
        ));
    }
    None
}

/// The per-operation classic fee cap `init` writes into a mainnet profile.
///
/// A mainnet classic stage refuses to sign or send without a cap, so a
/// freshly initialized mainnet profile carries one; the operator raises or
/// lowers it in the profile file.
const MAINNET_CLASSIC_MAX_FEE_PER_OP_STROOPS: u32 = 10_000;

/// Builds the profile `init` writes and checks its endpoints against the
/// endpoint rule the loader applies.
///
/// Signer and nonce references come from the shared
/// [`KeyringEntryRef::default_signer`] / [`KeyringEntryRef::default_nonce`]
/// derivations. These are the helpers the loader's synthesised first-run
/// fallback uses, with the placeholder `"default"` account; the named builders
/// derive the five security-substrate references from `profile_name`.
///
/// # Errors
///
/// - `validation.mainnet_rpc_url_required` for `--network mainnet` without
///   `--rpc-url`. [`init_refusal`] reports this first on the command path.
/// - `validation.config_invalid` for the `rpc_url` component when the URL
///   breaks the endpoint rule. The message names the field and the rule,
///   never the URL.
fn build_profile(args: &InitArgs, profile_name: &str) -> Result<Profile, WalletError> {
    let signer = KeyringEntryRef::default_signer(profile_name);
    let nonce = KeyringEntryRef::default_nonce(profile_name);

    let mut builder = match args.network {
        TargetNetwork::Testnet => {
            let builder = Profile::builder_testnet_named(
                profile_name,
                &signer.service,
                &signer.account,
                &nonce.service,
                &nonce.account,
            );
            match &args.rpc_url {
                Some(url) => builder.rpc_url(url.clone()),
                None => builder,
            }
        }
        TargetNetwork::Mainnet => {
            let rpc_url = args.rpc_url.clone().ok_or(WalletError::Validation(
                ValidationError::MainnetRpcUrlRequired,
            ))?;
            Profile::builder_mainnet_named(
                profile_name,
                rpc_url,
                &signer.service,
                &signer.account,
                &nonce.service,
                &nonce.account,
            )
            .classic_max_fee_per_op_stroops(Some(MAINNET_CLASSIC_MAX_FEE_PER_OP_STROOPS))
        }
    };
    if args.engine == PolicyEngineKind::Noop {
        builder = builder.with_noop_engine();
    }
    let profile = builder.build();

    // The same rule the loader applies at load time, so `init` never persists
    // a file the loader would then refuse.
    profile.validate_endpoint_urls().map_err(|e| {
        WalletError::Validation(ValidationError::ConfigInvalid {
            component: "rpc_url",
            reason: e.to_string(),
        })
    })?;
    Ok(profile)
}

/// The spending flags given in `args`, in help order.
fn spending_flags(args: &InitArgs) -> Vec<&'static str> {
    [
        ("--preset", args.preset.is_some()),
        ("--asset", args.asset.is_some()),
        ("--tolerated-loss", args.tolerated_loss.is_some()),
        ("--typical-payment", args.typical_payment.is_some()),
        ("--unlisted-budget", args.unlisted_budget.is_some()),
        ("--total-budget", args.total_budget.is_some()),
        ("--output", args.output.is_some()),
    ]
    .into_iter()
    .filter_map(|(flag, given)| given.then_some(flag))
    .collect()
}

/// Refuses the spending flags outside `--network mainnet --engine v1`, where
/// no policy body is generated. The message names the flags, never their
/// values.
fn spending_flag_refusal(args: &InitArgs) -> Option<Envelope<()>> {
    let flags = spending_flags(args);
    (!flags.is_empty()).then(|| {
        Envelope::err_raw(
            "validation.usage_error",
            format!(
                "{}: these flags apply only to --network mainnet --engine v1",
                flags.join(", ")
            ),
        )
    })
}

/// The envelope of a refused preset input. An input that a terminal could
/// supply names its flag and the prompt.
fn preset_refusal(error: &PresetError) -> Envelope<()> {
    let message = match error {
        PresetError::InputRequired(name) => format!(
            "{error}; pass --{}, or run at a terminal to answer its prompt",
            name.replace('_', "-")
        ),
        PresetError::Invalid(_) => error.to_string(),
    };
    Envelope::err_raw(error.code(), message)
}

/// The envelope of an internal failure.
fn internal_refusal(detail: String) -> Envelope<()> {
    Envelope::err(&WalletError::Internal(InternalError::UnexpectedState {
        detail,
    }))
}

/// Asks the operator at a terminal, or refuses without one.
struct Prompter<'a, F> {
    terminal: bool,
    stderr: &'a mut dyn Write,
    read_line: &'a mut F,
}

impl<F, Fut> Prompter<'_, F>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<Option<String>>>,
{
    /// Writes `prompt` to stderr, flushes, and reads one answer.
    ///
    /// The answer loses its line ending, `\r\n` from a Windows terminal
    /// included, and then its surrounding spaces.
    ///
    /// # Errors
    ///
    /// [`PresetError::InputRequired`] naming `input` without a terminal, and
    /// when the prompt cannot be written or the answer cannot be read, end
    /// of input included.
    async fn ask(&mut self, prompt: &str, input: &'static str) -> Result<String, PresetError> {
        let required = || PresetError::InputRequired(input);
        if !self.terminal {
            return Err(required());
        }
        self.stderr
            .write_all(prompt.as_bytes())
            .and_then(|()| self.stderr.flush())
            .map_err(|_| required())?;
        match (self.read_line)().await {
            Ok(Some(line)) => Ok(line
                .trim_end_matches(['\r', '\n'])
                .trim_matches(' ')
                .to_owned()),
            Ok(None) | Err(_) => Err(required()),
        }
    }
}

/// Resolves the preset inputs from the flags and, at a terminal, the
/// prompts, and derives the limits.
///
/// The flags are checked before any prompt: an input [`presets::derive`]
/// refuses as invalid never reaches a prompt. The prompts then ask for a
/// missing XLM tolerated loss and typical payment, in that order. A missing
/// unlisted choice of an api preset follows, then a missing total budget
/// choice. Without a terminal the total budget is chosen and every
/// other missing input refuses.
async fn preset_spending<F, Fut>(
    args: &InitArgs,
    stderr: &mut dyn Write,
    read_line: &mut F,
) -> Result<DerivedSpending, PresetError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<Option<String>>>,
{
    let preset = presets::find_preset(args.preset.as_deref().unwrap_or(DEFAULT_PRESET))?;
    let asset_arg = args.asset.unwrap_or(PresetAssetArg::Usdc);
    let code = asset_arg.code();
    let amount = |flag: &Option<String>| flag.as_deref().map(presets::parse_amount).transpose();
    let mut input = PresetInput {
        preset,
        asset: match asset_arg {
            PresetAssetArg::Usdc => PresetAsset::Usdc {
                issuer: USDC_MAINNET_ISSUER.to_owned(),
            },
            PresetAssetArg::Xlm => PresetAsset::Native,
        },
        tolerated_loss_stroops: amount(&args.tolerated_loss)?,
        typical_payment_stroops: amount(&args.typical_payment)?,
        unlisted_budget: args.unlisted_budget == Some(YesNo::Yes),
        total_budget: args.total_budget != Some(YesNo::No),
    };
    if let Err(error @ PresetError::Invalid(_)) = presets::derive(&input) {
        return Err(error);
    }
    let mut prompter = Prompter {
        terminal: stdin_and_stderr_are_terminals(),
        stderr,
        read_line,
    };
    if input.asset == PresetAsset::Native {
        if input.tolerated_loss_stroops.is_none() {
            let answer = prompter
                .ask("Tolerated loss in XLM: ", "tolerated_loss")
                .await?;
            input.tolerated_loss_stroops = Some(presets::parse_amount(&answer)?);
        }
        if input.typical_payment_stroops.is_none() {
            let answer = prompter
                .ask("Typical payment in XLM: ", "typical_payment")
                .await?;
            input.typical_payment_stroops = Some(presets::parse_amount(&answer)?);
        }
    }
    if preset.archetype == Archetype::Api && args.unlisted_budget.is_none() {
        let offered = presets::derive(&PresetInput {
            unlisted_budget: true,
            ..input.clone()
        })?;
        let budget = offered.unlisted.ok_or_else(|| {
            PresetError::Invalid("the api preset derives no unlisted budget".to_owned())
        })?;
        let question = format!(
            "Allow payments to unlisted recipients up to {} {code} per rolling day, shared by \
             all payment tools, at most {} {code} per payment? [yes/no]: ",
            presets::format_amount(budget.per_day_stroops),
            presets::format_amount(budget.per_payment_stroops)
        );
        let answer = prompter.ask(&question, "unlisted_budget").await?;
        input.unlisted_budget = if answer.eq_ignore_ascii_case("yes") {
            true
        } else if answer.eq_ignore_ascii_case("no") {
            false
        } else {
            return Err(PresetError::Invalid(
                "the unlisted budget answer must be yes or no".to_owned(),
            ));
        };
    }
    if args.total_budget.is_none() && prompter.terminal {
        let loss = input
            .tolerated_loss_stroops
            .unwrap_or(preset.tolerated_loss_stroops);
        let question = format!(
            "Limit total spending to {} {code} for this policy? Signing the same policy body \
             again keeps the allocation; a different digest starts another. [Y/n]: ",
            presets::format_amount(loss)
        );
        let answer = prompter.ask(&question, "total_budget").await?;
        input.total_budget = match answer.to_ascii_lowercase().as_str() {
            "" | "y" | "yes" => true,
            "n" | "no" => false,
            _ => {
                return Err(PresetError::Invalid(
                    "the total budget answer must be y, yes, n, or no".to_owned(),
                ));
            }
        };
    }
    presets::derive(&input)
}

/// The generated policy body of a mainnet V1 profile with its preview.
struct GeneratedPolicy {
    body: String,
    summary: SpendingSummary,
    plan: PresetPlan,
}

/// Derives the preset, writes its body, and checks that the body loads.
async fn generate_policy<F, Fut>(
    args: &InitArgs,
    profile_name: &str,
    stderr: &mut dyn Write,
    read_line: &mut F,
) -> Result<GeneratedPolicy, Envelope<()>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<Option<String>>>,
{
    let derived = preset_spending(args, stderr, read_line)
        .await
        .map_err(|error| preset_refusal(&error))?;
    let body = presets::policy_body(profile_name, &derived);
    let does_not_load = |detail: String| {
        internal_refusal(format!("the generated policy body does not load: {detail}"))
    };
    validate_unsigned_policy(&body, profile_name, MAINNET_PASSPHRASE)
        .map_err(|error| does_not_load(error.to_string()))?;
    let document = body
        .parse::<toml_edit::DocumentMut>()
        .map_err(|error| does_not_load(error.to_string()))?;
    Ok(GeneratedPolicy {
        summary: presets::summarize(&document, MAINNET_PASSPHRASE, AuthorityStatus::Draft),
        plan: presets::plan(&derived),
        body,
    })
}

/// Writes the generated body to `{policy_dir}/{profile_name}.toml` without
/// replacing a file.
///
/// The body goes to a temporary file in the directory, is synced, and is
/// then persisted only where no file exists. An existing file of equal
/// bytes is kept, so a rerun after a failed profile write continues.
///
/// # Errors
///
/// `profile.policy_already_exists` for an existing file of other or
/// unreadable content, and `profile.preset_write_failed` for any other I/O
/// failure. Neither writes the profile.
fn write_policy_file(
    policy_dir: &Path,
    profile_name: &str,
    body: &str,
) -> Result<(), Envelope<()>> {
    let path = policy_dir.join(format!("{profile_name}.toml"));
    let failed = |error: &dyn std::fmt::Display| {
        Envelope::err_raw(
            "profile.preset_write_failed",
            format!(
                "the policy file {} could not be written: {error}; the profile was not written",
                path.display()
            ),
        )
    };
    std::fs::create_dir_all(policy_dir).map_err(|e| failed(&e))?;
    let mut file = tempfile::NamedTempFile::new_in(policy_dir).map_err(|e| failed(&e))?;
    file.write_all(body.as_bytes()).map_err(|e| failed(&e))?;
    file.as_file().sync_all().map_err(|e| failed(&e))?;
    match file.persist_noclobber(&path) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
            match std::fs::read(&path) {
                Ok(existing) if existing == body.as_bytes() => Ok(()),
                _ => Err(Envelope::err_raw(
                    "profile.policy_already_exists",
                    format!(
                        "the policy file {} holds other content; the profile was not written",
                        path.display()
                    ),
                )),
            }
        }
        Err(error) => Err(failed(&error.error)),
    }
}

/// Testable core of [`run`] with the directories, the stderr writer, and
/// the answer reader injected.
///
/// Production callers use [`run`], which resolves the real OS-conventional
/// directories and reads answers from the terminal. Tests inject fresh
/// temporary directories so unit tests never read or write the canonical
/// data root.
///
/// A mainnet V1 profile also gets the generated policy body. Its preview
/// reaches stderr before the policy file, the policy file before the
/// profile, and the profile before the envelope. Every refusal after the
/// preview carries it at `error.details.preview`.
async fn run_with_dependencies<F, Fut>(
    args: &InitArgs,
    profile_dir: &Path,
    policy_dir: &Path,
    stderr: &mut dyn Write,
    mut read_line: F,
) -> i32
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<Option<String>>>,
{
    // `--profile`, then `STELLAR_AGENT_PROFILE`, then `"default"`.
    let profile_name = resolve_profile_name(args.profile.as_deref()).name;

    if let Some(err) = init_refusal(args, &profile_name, profile_dir) {
        render::render_json(&Envelope::<()>::err(&err));
        return 1;
    }

    // ── Build the profile and apply the endpoint rule ────────────────────────
    let profile = match build_profile(args, &profile_name) {
        Ok(profile) => profile,
        Err(err) => {
            render::render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

    // ── Generate, preview, and write the policy body on mainnet V1 ───────────
    let mainnet_v1 = args.network == TargetNetwork::Mainnet && args.engine == PolicyEngineKind::V1;
    if !mainnet_v1 && let Some(refusal) = spending_flag_refusal(args) {
        render::render_json(&refusal);
        return 1;
    }
    let generated = if mainnet_v1 {
        match generate_policy(args, &profile_name, &mut *stderr, &mut read_line).await {
            Ok(generated) => Some(generated),
            Err(refusal) => {
                render::render_json(&refusal);
                return 1;
            }
        }
    } else {
        None
    };
    let mut preview = SpendingPreview::new(stderr);
    if let Some(generated) = &generated {
        if let Err((code, message)) = preview.show(
            Some(&generated.summary),
            Some(&generated.plan),
            args.output.unwrap_or(OutputFormat::Json),
        ) {
            render::render_json(&Envelope::<()>::err_raw(code, message));
            return 1;
        }
        if let Err(refusal) = write_policy_file(policy_dir, &profile_name, &generated.body) {
            render::render_json(&with_shown_preview(refusal, preview.shown()));
            return 1;
        }
    }

    // ── Persist (no-clobber: atomic refusal if a file appeared meanwhile) ────
    let written_path = match loader::save_new_to_dir(&profile_name, &profile, profile_dir) {
        Ok(p) => p,
        Err(loader::ProfileSaveError::AlreadyExists { .. }) => {
            let err = WalletError::Validation(ValidationError::ProfileAlreadyExists);
            render::render_json(&with_shown_preview(
                Envelope::<()>::err(&err),
                preview.shown(),
            ));
            return 1;
        }
        Err(e) => {
            let refusal = internal_refusal(format!("failed to write the profile: {e}"));
            render::render_json(&with_shown_preview(refusal, preview.shown()));
            return 1;
        }
    };

    tracing::info!(
        profile = %profile_name,
        chain_id = %profile.chain_id,
        engine = %profile.policy.engine,
        "profile initialised"
    );
    let (spending_summary, plan) = generated.map_or((None, None), |generated| {
        (Some(generated.summary), Some(generated.plan))
    });
    render::render_json(&Envelope::ok(InitData {
        profile: profile_name.clone(),
        path: written_path.display().to_string(),
        chain_id: profile.chain_id.caip2_str().to_owned(),
        rpc_url: redact_url_authority(&profile.rpc_url),
        engine: profile.policy.engine.to_string(),
        next_steps: next_steps(&profile_name, args.engine, args.network),
        spending_summary,
        plan,
    }));
    0
}

/// The enrollment guidance `init` prints for a new profile, in the order the
/// steps must run.
///
/// Both engines list `rotate-audit-key`, then `enroll-signer`. The audit key
/// must exist before the first key-writing command so its audit row is written.
/// `init` writes the keyring coordinate; rotation mints the key material.
/// `rotate-nonce-key` follows, because MCP
/// payment simulation requires the commit-nonce key. The V1 list then names
/// owner enrollment, attestation key rotation, the policy file `sign-policy`
/// reads, and policy signing, in that order. On testnet the operator creates
/// a version 1 policy file; on mainnet `init` has generated a version 2 body
/// to review. A mainnet V1 profile adds the signer binding, the oracle
/// setting, and what running without it costs.
fn next_steps(profile_name: &str, engine: PolicyEngineKind, network: TargetNetwork) -> Vec<String> {
    let mut steps = vec![
        format!(
            "Run `stellar-agent profile rotate-audit-key {profile_name}` to mint the audit-log \
             hash-chain key (required before any signing verb will proceed)."
        ),
        format!(
            "Run `stellar-agent profile enroll-signer --profile {profile_name} --secret-env \
             <VAR>` to register the MCP signer seed."
        ),
        format!(
            "Run `stellar-agent profile rotate-nonce-key {profile_name}` to mint the \
             commit-nonce key (required before MCP payment simulation)."
        ),
    ];
    if engine == PolicyEngineKind::V1 {
        steps.push(format!(
            "Run `stellar-agent profile enroll-owner-key --profile {profile_name} --secret-env \
             <VAR>` to enroll the policy-file owner key."
        ));
        steps.push(format!(
            "Run `stellar-agent profile rotate-attestation-key {profile_name}` to mint the \
             approval-attestation key."
        ));
        steps.push(if network == TargetNetwork::Mainnet {
            format!(
                "Review the generated policy file `policies/{profile_name}.toml` in the wallet's \
                 state directory, with `version = 2` and `scope = \"profile:{profile_name}\"` \
                 (see \"Set up mainnet writes\" in the getting-started guide)."
            )
        } else {
            format!(
                "Create the V1 policy file `policies/{profile_name}.toml` in the wallet's state \
                 directory, with `version = 1` and `scope = \"profile:{profile_name}\"` (see \
                 \"Create the V1 policy file\" in the getting-started guide)."
            )
        });
        steps.push(format!(
            "Run `stellar-agent profile sign-policy --profile {profile_name} --secret-env \
             <VAR>` to sign the V1 policy file."
        ));
        if network == TargetNetwork::Mainnet {
            steps.push(format!(
                "Run `stellar-agent profile bind-signer --profile {profile_name} --owner-secret-env <VAR>` before `profile enable-mainnet` to bind the signer to its owner."
            ));
            steps.push(
                "Set `oracle_provider_url`, `[providers.oracle]`, and `[providers.primary]` in \
                 the profile file. Choose an independently administered endpoint on a different \
                 host; `stellar-agent profile enable-mainnet` and every mainnet write refuse a \
                 mainnet profile without `oracle_provider_url` with \
                 `profile.mainnet_oracle_required`."
                    .to_owned(),
            );
        }
    }
    steps
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use std::path::PathBuf;

    use stellar_agent_core::profile::loader::load_from_dir;

    use super::*;

    fn args(profile: &str) -> InitArgs {
        InitArgs {
            profile: Some(profile.to_owned()),
            network: TargetNetwork::Testnet,
            rpc_url: None,
            engine: PolicyEngineKind::V1,
            preset: None,
            asset: None,
            tolerated_loss: None,
            typical_payment: None,
            unlisted_budget: None,
            total_budget: None,
            output: None,
        }
    }

    /// Drives [`run_with_dependencies`] on a current-thread runtime with the
    /// policy directory `dir/policies`, a captured stderr, no terminal, and
    /// a reader at end of input.
    fn run_init(args: &InitArgs, dir: &Path) -> i32 {
        let _tty = crate::common::tty::tests::test_tty(false, false);
        let mut stderr = Vec::new();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(run_with_dependencies(
                args,
                dir,
                &dir.join("policies"),
                &mut stderr,
                || async { Ok(None) },
            ))
    }

    /// The name `run_with_dependencies` resolves for these args — always the
    /// explicit one, since `args` always sets it.
    fn resolved_name(args: &InitArgs) -> String {
        resolve_profile_name(args.profile.as_deref()).name
    }

    /// Sentinel URLs whose every component must stay out of a refusal.
    const SENTINEL_HTTP: &str =
        "http://SENTINEL-USER:SENTINEL-PASS@sentinel-host.invalid/SENTINEL-PATH?k=SENTINEL-QUERY";
    const SENTINEL_HTTPS: &str =
        "https://SENTINEL-USER:SENTINEL-PASS@sentinel-host.invalid/SENTINEL-PATH?k=SENTINEL-QUERY";

    /// Asserts that no sentinel component reaches `text`. Case-insensitive,
    /// because the `url` crate lowercases the host.
    fn assert_no_sentinel(text: &str) {
        assert!(
            !text.to_ascii_lowercase().contains("sentinel"),
            "a sentinel URL component leaked: {text}"
        );
    }

    /// Asserts `err` and its rendered envelope carry no sentinel component.
    fn assert_refusal_omits_the_url(err: &WalletError) {
        assert_no_sentinel(&err.to_string());
        assert_no_sentinel(&format!("{err:?}"));
        assert_no_sentinel(&serde_json::to_string(&Envelope::<()>::err(err)).unwrap());
    }

    /// RAII env-var guard; `#[serial]` on every test using it prevents
    /// concurrent env access.
    struct EnvGuard {
        var: String,
    }
    impl EnvGuard {
        #[allow(
            unsafe_code,
            reason = "test-only env mutation; #[serial] prevents concurrent access"
        )]
        fn set(var: String, value: &std::ffi::OsStr) -> Self {
            // SAFETY: serialised by #[serial]; no concurrent env access.
            unsafe {
                std::env::set_var(&var, value);
            }
            Self { var }
        }
    }
    impl Drop for EnvGuard {
        #[allow(unsafe_code, reason = "test-only env cleanup")]
        fn drop(&mut self) {
            // SAFETY: same as set(); serialised by #[serial].
            unsafe {
                std::env::remove_var(&self.var);
            }
        }
    }

    /// The test-gated `STELLAR_AGENT_HOME` override reaches the audit-path
    /// resolution: with the variable set, the per-profile audit default
    /// resolves under the redirected root, so tests that follow the
    /// documented override never write audit rows to the real host location.
    #[test]
    #[serial_test::serial]
    fn audit_path_resolution_honors_the_test_home_override() {
        let home = tempfile::tempdir().unwrap();
        stellar_agent_test_support::sandbox::mark_sandbox(home.path()).unwrap();
        let _guard = EnvGuard::set("STELLAR_AGENT_HOME".to_owned(), home.path().as_os_str());

        let path = stellar_agent_core::profile::schema::default_audit_log_path_for("override-x");
        assert!(
            path.starts_with(home.path()),
            "audit path must resolve under the overridden home; got: {path:?}"
        );
        assert_eq!(path.file_name().unwrap(), "override-x.jsonl");
        assert_eq!(path.parent().unwrap().file_name().unwrap(), "audit");
    }

    #[test]
    #[serial_test::serial]
    fn init_on_clean_dir_creates_a_loadable_v1_profile_with_derived_refs() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let dir = tempfile::tempdir().unwrap();
        let code = run_init(&args("acceptance"), dir.path());
        assert_eq!(code, 0, "init must succeed on a clean directory");

        let path = dir.path().join("acceptance.toml");
        assert!(path.exists(), "profile file must be created");

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            raw.contains("version = 2"),
            "must carry version = 2:\n{raw}"
        );
        assert!(
            raw.contains("[policy]"),
            "must carry a [policy] block:\n{raw}"
        );
        assert!(
            raw.contains("engine = \"v1\""),
            "default engine must be v1:\n{raw}"
        );
        assert!(
            raw.contains("stellar-agent-signer-acceptance"),
            "signer service must be derived from the profile name:\n{raw}"
        );
        assert!(
            raw.contains("stellar-agent-nonce-acceptance"),
            "nonce service must be derived from the profile name:\n{raw}"
        );
        assert!(
            raw.contains("stellar-agent-audit-acceptance"),
            "audit key ref must be derived from the profile name:\n{raw}"
        );
        assert!(
            raw.contains("stellar-agent-owner-acceptance"),
            "owner key ref must be derived from the profile name:\n{raw}"
        );
        assert!(
            raw.contains("stellar-agent-attestation-acceptance"),
            "attestation key ref must be derived from the profile name:\n{raw}"
        );
        assert!(
            raw.contains("stellar-agent-counterparty-acceptance"),
            "counterparty key ref must be derived from the profile name:\n{raw}"
        );

        // Loadable through the real loader, not just readable as text.
        let loaded = load_from_dir("acceptance", dir.path(), None).unwrap();
        assert_eq!(loaded.version, 2);
        assert_eq!(loaded.policy.engine, PolicyEngineKind::V1);
        assert_eq!(loaded.mcp_signer_default.account, "default");
    }

    #[test]
    #[serial_test::serial]
    fn init_default_name_is_loadable_without_the_synthesised_fallback() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let dir = tempfile::tempdir().unwrap();
        let code = run_init(&args("default"), dir.path());
        assert_eq!(code, 0);

        // The synthesised fallback is only reached on `ProfileLoadError::NotFound`
        // (see `load_default_or_testnet_fallback`); asserting `load_from_dir`
        // succeeds directly proves the persisted file — not the fallback — is
        // what a subsequent load resolves.
        let loaded = load_from_dir("default", dir.path(), None)
            .expect("the persisted default.toml must load directly, not via NotFound + fallback");
        assert_eq!(
            loaded.mcp_signer_default.service,
            "stellar-agent-signer-default"
        );
    }

    #[test]
    #[serial_test::serial]
    fn init_refuses_when_file_already_exists_and_leaves_it_untouched() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let dir = tempfile::tempdir().unwrap();
        let code = run_init(&args("dup"), dir.path());
        assert_eq!(code, 0, "first init must succeed");

        let path = dir.path().join("dup.toml");
        let before = std::fs::read_to_string(&path).unwrap();

        let code = run_init(&args("dup"), dir.path());
        assert_eq!(code, 1, "second init on the same name must refuse");

        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(before, after, "a refused init must not modify the file");
    }

    #[test]
    fn init_mainnet_without_rpc_url_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = args("mainnet-guard");
        a.network = TargetNetwork::Mainnet;
        a.rpc_url = None;

        let code = run_init(&a, dir.path());
        assert_eq!(code, 1, "mainnet without --rpc-url must refuse");
        assert!(
            !dir.path().join("mainnet-guard.toml").exists(),
            "a refused mainnet init must not write a file"
        );
    }

    // ── Typed refusal pins (init_refusal and build_profile) ──────────────────
    // The run()-level tests above prove the exit code end to end; these pin
    // the SPECIFIC typed refusal so a guard swap cannot pass unnoticed behind
    // an unrelated exit-1 path.

    /// Mainnet without `--rpc-url` refuses with its exact wire code.
    #[test]
    fn refusal_mainnet_without_rpc_url_yields_typed_code() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = args("pin-mainnet");
        a.network = TargetNetwork::Mainnet;
        a.rpc_url = None;
        let err = init_refusal(&a, resolved_name(&a).as_str(), dir.path()).expect("must refuse");
        assert_eq!(err.code(), "validation.mainnet_rpc_url_required");
    }

    /// A plaintext mainnet endpoint breaks the endpoint rule and refuses with
    /// the config-invalid code.
    #[test]
    #[serial_test::serial]
    fn build_mainnet_plaintext_rpc_url_yields_typed_code() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let mut a = args("pin-plaintext");
        a.network = TargetNetwork::Mainnet;
        a.rpc_url = Some("http://mainnet.example.com/rpc".to_owned());
        let err = build_profile(&a, &resolved_name(&a)).expect_err("must refuse");
        assert_eq!(err.code(), "validation.config_invalid");
        assert!(
            err.to_string()
                .contains("must be an https URL on a mainnet profile"),
            "{err}"
        );
    }

    /// The plaintext refusal names no part of the URL, so a credential in it
    /// never reaches the envelope.
    #[test]
    #[serial_test::serial]
    fn build_mainnet_plaintext_rpc_url_omits_the_url() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let mut a = args("redact-plaintext");
        a.network = TargetNetwork::Mainnet;
        a.rpc_url = Some(SENTINEL_HTTP.to_owned());
        let err = build_profile(&a, &resolved_name(&a)).expect_err("must refuse");
        assert_eq!(err.code(), "validation.config_invalid");
        assert_refusal_omits_the_url(&err);
    }

    /// The flag parser accepts an `ftp://` URL; the endpoint rule refuses it
    /// on every chain.
    #[test]
    #[serial_test::serial]
    fn build_unsupported_scheme_yields_typed_code() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        for network in [TargetNetwork::Testnet, TargetNetwork::Mainnet] {
            let mut a = args("pin-ftp");
            a.network = network;
            a.rpc_url = Some("ftp://mainnet.example.com".to_owned());
            let err = build_profile(&a, &resolved_name(&a)).expect_err("must refuse");
            assert_eq!(err.code(), "validation.config_invalid", "{network}");
            assert!(
                err.to_string().contains("must be an http or https URL"),
                "{network}: {err}"
            );
        }
    }

    /// Userinfo in a mainnet URL breaks the endpoint rule. The flag parser
    /// refuses such a URL before the command runs; this pins the rule itself
    /// for a URL that reaches `build_profile`.
    #[test]
    #[serial_test::serial]
    fn build_mainnet_rpc_url_with_userinfo_yields_typed_code() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let mut a = args("pin-userinfo");
        a.network = TargetNetwork::Mainnet;
        a.rpc_url = Some(SENTINEL_HTTPS.to_owned());
        let err = build_profile(&a, &resolved_name(&a)).expect_err("must refuse");
        assert_eq!(err.code(), "validation.config_invalid");
        assert!(err.to_string().contains("username or password"), "{err}");
        assert_refusal_omits_the_url(&err);
    }

    /// `build_profile` refuses mainnet without a URL on its own, with the
    /// same code `init_refusal` reports first on the command path.
    #[test]
    #[serial_test::serial]
    fn build_mainnet_without_rpc_url_yields_typed_code() {
        let mut a = args("pin-build-mainnet");
        a.network = TargetNetwork::Mainnet;
        a.rpc_url = None;
        let err = build_profile(&a, &resolved_name(&a)).expect_err("must refuse");
        assert_eq!(err.code(), "validation.mainnet_rpc_url_required");
    }

    /// Each endpoint-rule refusal on the command path exits 1 and writes no
    /// file.
    #[test]
    #[serial_test::serial]
    fn init_endpoint_rule_refusals_write_no_file() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        for (network, url) in [
            (TargetNetwork::Testnet, "ftp://mainnet.example.com"),
            (TargetNetwork::Mainnet, "ftp://mainnet.example.com"),
            (TargetNetwork::Mainnet, "http://mainnet.example.com/rpc"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut a = args("endpoint-refused");
            a.network = network;
            a.rpc_url = Some(url.to_owned());
            let code = run_init(&a, dir.path());
            assert_eq!(code, 1, "{network} `{url}` must be refused");
            assert!(
                !dir.path().join("endpoint-refused.toml").exists(),
                "{network} `{url}`: a refused init must not write a file"
            );
        }
    }

    /// An existing destination refuses before the endpoint rule runs: a
    /// parser-accepted `http://` mainnet URL still reports
    /// `validation.profile_already_exists`, and the file is untouched.
    #[test]
    fn init_refusal_reports_an_existing_destination_before_the_endpoint_rule() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pin-order.toml");
        std::fs::write(&path, "version = 2\n").unwrap();
        let mut a = args("pin-order");
        a.network = TargetNetwork::Mainnet;
        a.rpc_url = Some("http://mainnet.example.com/rpc".to_owned());

        let err = init_refusal(&a, resolved_name(&a).as_str(), dir.path()).expect("must refuse");
        assert_eq!(err.code(), "validation.profile_already_exists");

        assert_eq!(run_init(&a, dir.path()), 1);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "version = 2\n");
    }

    /// An existing destination refuses with its exact wire code.
    #[test]
    fn refusal_existing_profile_yields_typed_code() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pin-exists.toml"), "version = 2\n").unwrap();
        let a = args("pin-exists");
        let err = init_refusal(&a, resolved_name(&a).as_str(), dir.path()).expect("must refuse");
        assert_eq!(err.code(), "validation.profile_already_exists");
    }

    /// An unsafe profile name refuses with its exact wire code, naming the
    /// `profile` component so it is distinguishable from the other
    /// `validation.config_invalid` refusal this command emits, and no refusal
    /// fires for a clean state (the gate passes through).
    #[test]
    fn refusal_unsafe_name_yields_typed_code_and_clean_state_passes() {
        let dir = tempfile::tempdir().unwrap();
        let unsafe_name = args("../escape");
        let err = init_refusal(
            &unsafe_name,
            resolved_name(&unsafe_name).as_str(),
            dir.path(),
        )
        .expect("must refuse");
        assert_eq!(err.code(), "validation.config_invalid");
        let message = err.to_string();
        assert!(
            message.contains("configuration invalid for 'profile'"),
            "the refusal must name the profile component: {message}"
        );
        assert!(
            message.contains("the profile name is not a valid profile name: "),
            "the refusal must state the rule the name breaks: {message}"
        );
        assert!(
            !message.contains("../escape"),
            "the refusal must not repeat the refused name: {message}"
        );
        let clean = args("clean-name");
        assert!(
            init_refusal(&clean, resolved_name(&clean).as_str(), dir.path()).is_none(),
            "a clean state must pass the refusal gate"
        );
    }

    #[test]
    #[serial_test::serial]
    fn init_mainnet_with_rpc_url_writes_the_supplied_url() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let dir = tempfile::tempdir().unwrap();
        let mut a = args("mainnet-ok");
        a.network = TargetNetwork::Mainnet;
        a.rpc_url = Some("https://mainnet.example.com/rpc".to_owned());
        a.unlisted_budget = Some(YesNo::No);

        let code = run_init(&a, dir.path());
        assert_eq!(code, 0, "mainnet with --rpc-url must succeed");

        let loaded = load_from_dir("mainnet-ok", dir.path(), None).unwrap();
        assert_eq!(loaded.chain_id.caip2_str(), "stellar:mainnet");
        assert_eq!(loaded.rpc_url, "https://mainnet.example.com/rpc");
    }

    /// A mainnet profile is written with the per-operation fee cap; a testnet
    /// profile without one.
    #[test]
    #[serial_test::serial]
    fn profile_init_mainnet_writes_fee_cap() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let dir = tempfile::tempdir().unwrap();
        let mut a = args("mainnet-cap");
        a.network = TargetNetwork::Mainnet;
        a.rpc_url = Some("https://mainnet.example.com/rpc".to_owned());
        a.unlisted_budget = Some(YesNo::No);
        assert_eq!(run_init(&a, dir.path()), 0);

        let raw = std::fs::read_to_string(dir.path().join("mainnet-cap.toml")).unwrap();
        assert!(
            raw.lines()
                .any(|line| line.trim() == "classic_max_fee_per_op_stroops = 10000"),
            "raw toml:\n{raw}"
        );
        let loaded = load_from_dir("mainnet-cap", dir.path(), None).unwrap();
        assert_eq!(loaded.classic_max_fee_per_op_stroops, Some(10_000));

        assert_eq!(run_init(&args("testnet-cap"), dir.path()), 0);
        let raw = std::fs::read_to_string(dir.path().join("testnet-cap.toml")).unwrap();
        assert!(
            !raw.contains("classic_max_fee_per_op_stroops"),
            "raw toml:\n{raw}"
        );
        let loaded = load_from_dir("testnet-cap", dir.path(), None).unwrap();
        assert_eq!(loaded.classic_max_fee_per_op_stroops, None);
    }

    #[test]
    #[serial_test::serial]
    fn init_engine_flag_default_writes_v1() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let dir = tempfile::tempdir().unwrap();
        let code = run_init(&args("engine-default"), dir.path());
        assert_eq!(code, 0);

        let raw = std::fs::read_to_string(dir.path().join("engine-default.toml")).unwrap();
        assert!(raw.contains("engine = \"v1\""), "raw toml:\n{raw}");
    }

    #[test]
    #[serial_test::serial]
    fn init_engine_noop_writes_noop() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let dir = tempfile::tempdir().unwrap();
        let mut a = args("engine-noop");
        a.engine = PolicyEngineKind::Noop;

        let code = run_init(&a, dir.path());
        assert_eq!(code, 0);

        let raw = std::fs::read_to_string(dir.path().join("engine-noop.toml")).unwrap();
        assert!(raw.contains("engine = \"noop\""), "raw toml:\n{raw}");

        let loaded = load_from_dir("engine-noop", dir.path(), None).unwrap();
        assert_eq!(loaded.policy.engine, PolicyEngineKind::Noop);
    }

    #[test]
    fn init_invalid_profile_name_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let code = run_init(&args("../escape"), dir.path());
        assert_eq!(code, 1, "a path-traversal profile name must be refused");
    }

    #[test]
    #[serial_test::serial]
    fn init_testnet_default_rpc_url_when_omitted() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let dir = tempfile::tempdir().unwrap();
        let code = run_init(&args("testnet-default-rpc"), dir.path());
        assert_eq!(code, 0);

        let loaded = load_from_dir("testnet-default-rpc", dir.path(), None).unwrap();
        assert_eq!(
            loaded.rpc_url,
            stellar_agent_core::profile::caip2::TESTNET_RPC_URL
        );
    }

    #[test]
    #[serial_test::serial]
    fn init_testnet_explicit_rpc_url_overrides_default() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let dir = tempfile::tempdir().unwrap();
        let mut a = args("testnet-explicit-rpc");
        a.rpc_url = Some("https://custom-testnet-rpc.example.com".to_owned());

        let code = run_init(&a, dir.path());
        assert_eq!(code, 0);

        let loaded = load_from_dir("testnet-explicit-rpc", dir.path(), None).unwrap();
        assert_eq!(loaded.rpc_url, "https://custom-testnet-rpc.example.com");
    }

    /// Testnet accepts a plaintext endpoint: the HTTPS requirement is
    /// mainnet-only.
    #[test]
    #[serial_test::serial]
    fn init_testnet_plaintext_rpc_url_is_accepted() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let dir = tempfile::tempdir().unwrap();
        let mut a = args("testnet-plaintext-rpc");
        a.rpc_url = Some("http://127.0.0.1:8000".to_owned());

        let code = run_init(&a, dir.path());
        assert_eq!(code, 0);

        let loaded = load_from_dir("testnet-plaintext-rpc", dir.path(), None).unwrap();
        assert_eq!(loaded.rpc_url, "http://127.0.0.1:8000");
    }

    #[test]
    #[serial_test::serial]
    fn init_malformed_rpc_url_is_refused_before_write() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let dir = tempfile::tempdir().unwrap();
        let mut a = args("malformed-rpc");
        a.rpc_url = Some("not a url".to_owned());

        let code = run_init(&a, dir.path());
        assert_eq!(code, 1, "a malformed --rpc-url must be refused");
        assert!(
            !dir.path().join("malformed-rpc.toml").exists(),
            "a refused init must not write a file"
        );
    }

    /// Asserts each step names the matching marker, in order, and that no
    /// step is left over.
    fn assert_steps_in_order(steps: &[String], markers: &[&str]) {
        assert_eq!(steps.len(), markers.len(), "{steps:#?}");
        for (step, marker) in steps.iter().zip(markers) {
            assert!(step.contains(marker), "expected `{marker}` in: {step}");
        }
    }

    /// A `noop` profile lists the audit key, the signer, and the commit-nonce
    /// key, in that order, and nothing of the V1 setup.
    #[test]
    fn next_steps_for_noop_list_audit_signer_and_nonce_keys() {
        let steps = next_steps("alpha", PolicyEngineKind::Noop, TargetNetwork::Testnet);
        assert_steps_in_order(
            &steps,
            &[
                "profile rotate-audit-key alpha`",
                "profile enroll-signer --profile alpha ",
                "profile rotate-nonce-key alpha`",
            ],
        );
    }

    /// A V1 profile adds owner enrollment, the attestation key, the policy
    /// file, and policy signing, with the policy file right before
    /// `sign-policy`.
    #[test]
    fn next_steps_for_v1_create_the_policy_file_before_signing_it() {
        let steps = next_steps("alpha", PolicyEngineKind::V1, TargetNetwork::Testnet);
        assert_steps_in_order(
            &steps,
            &[
                "profile rotate-audit-key alpha`",
                "profile enroll-signer --profile alpha ",
                "profile rotate-nonce-key alpha`",
                "profile enroll-owner-key --profile alpha ",
                "profile rotate-attestation-key alpha`",
                "`policies/alpha.toml` in the wallet's state directory",
                "profile sign-policy --profile alpha ",
            ],
        );
        assert!(
            steps[5].contains("`scope = \"profile:alpha\"`"),
            "{}",
            steps[5]
        );
    }

    /// A mainnet V1 profile ends with the oracle setting.
    #[test]
    fn next_steps_for_mainnet_v1_end_with_the_oracle_setting() {
        let steps = next_steps("alpha", PolicyEngineKind::V1, TargetNetwork::Mainnet);
        assert_eq!(steps.len(), 9, "{steps:#?}");
        assert!(steps[7].contains("profile bind-signer --profile alpha --owner-secret-env <VAR>"));
        assert!(steps[8].contains("`oracle_provider_url`"), "{}", steps[8]);
        assert!(steps[8].contains("`[providers.oracle]`"), "{}", steps[8]);
        assert!(steps[8].contains("`[providers.primary]`"), "{}", steps[8]);
        assert!(steps[8].contains("different host"), "{}", steps[8]);
        assert!(
            steps[8].contains(
                "`stellar-agent profile enable-mainnet` and every mainnet write refuse a \
                 mainnet profile without `oracle_provider_url` with \
                 `profile.mainnet_oracle_required`"
            ),
            "{}",
            steps[8]
        );
        assert!(!steps[8].contains("skipped"), "{}", steps[8]);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn init_requested_name_marker_is_not_echoed() {
        let capture = stellar_agent_test_support::log_capture::CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(capture.clone())
            .finish();
        let _inert = stellar_agent_test_support::log_capture::inert_dispatcher();
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        use stellar_agent_test_support::rejected_value::{
            CREDENTIAL_MARKER, assert_no_marker, assert_no_marker_in_text,
        };
        let home = tempfile::tempdir().unwrap();
        stellar_agent_test_support::sandbox::mark_sandbox(home.path()).unwrap();
        let _guard = EnvGuard::set("STELLAR_AGENT_HOME".to_owned(), home.path().as_os_str());
        let mut input = args(CREDENTIAL_MARKER);
        input.network = TargetNetwork::Mainnet;
        render::take_rendered_for_test();
        assert_eq!(run(&input).await, 1);
        let output = render::take_rendered_for_test();
        assert_eq!(
            output[0]["error"]["code"],
            "validation.mainnet_rpc_url_required"
        );
        assert_eq!(
            output[0]["error"]["message"],
            "the mainnet profile requires an explicit RPC endpoint; set rpc_url in the profile file, or pass --rpc-url to profile init"
        );
        assert_no_marker_in_text(&format!("{output:?}"), CREDENTIAL_MARKER);
        let error = init_refusal(&input, CREDENTIAL_MARKER, &home.path().join("profiles"))
            .expect("the command's typed refusal is available");
        assert_no_marker(&error, CREDENTIAL_MARKER);
        let error = build_profile(&input, CREDENTIAL_MARKER).unwrap_err();
        assert_eq!(error.code(), "validation.mainnet_rpc_url_required");
        assert_no_marker(&error, CREDENTIAL_MARKER);
        input.network = TargetNetwork::Testnet;
        let profiles_dir = home.path().join("profiles");
        let occupied = profiles_dir.join(format!("{CREDENTIAL_MARKER}.toml"));
        std::fs::create_dir_all(&occupied).unwrap();
        assert_eq!(run(&input).await, 1);
        let output = render::take_rendered_for_test();
        assert_eq!(
            output[0]["error"]["code"],
            "validation.profile_already_exists"
        );
        assert_eq!(
            output[0]["error"]["message"],
            "the profile destination already exists; choose a different --profile name or remove the existing entry"
        );
        assert_no_marker_in_text(&format!("{output:?}"), CREDENTIAL_MARKER);
        let error = init_refusal(&input, CREDENTIAL_MARKER, &profiles_dir).unwrap();
        assert_no_marker(&error, CREDENTIAL_MARKER);
        std::fs::remove_dir(&occupied).unwrap();
        std::fs::remove_dir(&profiles_dir).unwrap();
        std::fs::write(home.path().join("profiles"), "obstruction").unwrap();
        assert_eq!(run(&input).await, 1);
        let output = render::take_rendered_for_test();
        assert_eq!(output[0]["error"]["code"], "internal.unexpected_state");
        let profile = build_profile(&input, CREDENTIAL_MARKER).unwrap();
        let error =
            loader::save_new_to_dir(CREDENTIAL_MARKER, &profile, &home.path().join("profiles"))
                .unwrap_err();
        assert_no_marker(&error, CREDENTIAL_MARKER);
        assert_eq!(
            output[0]["error"]["message"],
            format!("unexpected internal state: failed to write the profile: {error}")
        );
        assert_no_marker_in_text(&format!("{output:?}"), CREDENTIAL_MARKER);
        stellar_agent_test_support::rejected_value::assert_no_marker_in_text(
            &capture.captured_str(),
            "CREDMARKER7",
        );
    }

    /// A mainnet V1 profile on a valid endpoint.
    fn mainnet(profile: &str) -> InitArgs {
        let mut a = args(profile);
        a.network = TargetNetwork::Mainnet;
        a.rpc_url = Some("https://mainnet.example.com/rpc".to_owned());
        a
    }

    /// A reader that answers from `answers` in order, then reports end of
    /// input.
    fn queue(
        answers: &[&str],
    ) -> impl FnMut() -> std::future::Ready<io::Result<Option<String>>> + use<> {
        let mut answers: std::collections::VecDeque<String> =
            answers.iter().map(|a| (*a).to_owned()).collect();
        move || std::future::ready(Ok(answers.pop_front()))
    }

    /// What one init run printed and wrote.
    struct Outcome {
        code: i32,
        stderr: String,
        envelope: serde_json::Value,
    }

    impl Outcome {
        fn error_code(&self) -> &str {
            self.envelope["error"]["code"].as_str().unwrap_or("")
        }

        fn message(&self) -> &str {
            self.envelope["error"]["message"].as_str().unwrap_or("")
        }

        /// The JSON preview line on stderr, the last line written there.
        fn preview(&self) -> serde_json::Value {
            serde_json::from_str(self.stderr.lines().last().unwrap()).unwrap()
        }
    }

    /// Runs init with `profiles` and `policies` as the directories, the
    /// terminal state `terminal` for both streams, and `stderr` as the
    /// captured stream.
    async fn init_into<F, Fut>(
        a: &InitArgs,
        (profiles, policies): (&Path, &Path),
        terminal: bool,
        stderr: &mut dyn Write,
        reader: F,
    ) -> (i32, serde_json::Value)
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = io::Result<Option<String>>>,
    {
        let _tty = crate::common::tty::tests::test_tty(terminal, terminal);
        render::take_rendered_for_test();
        let code = run_with_dependencies(a, profiles, policies, stderr, reader).await;
        let mut rendered = render::take_rendered_for_test();
        assert_eq!(rendered.len(), 1, "{rendered:?}");
        (code, rendered.remove(0))
    }

    /// Runs init with `dir/profiles` and `dir/policies` and a captured
    /// stderr.
    async fn init_at<F, Fut>(a: &InitArgs, dir: &Path, terminal: bool, reader: F) -> Outcome
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = io::Result<Option<String>>>,
    {
        let mut stderr = Vec::new();
        let (code, envelope) = init_into(
            a,
            (&dir.join("profiles"), &dir.join("policies")),
            terminal,
            &mut stderr,
            reader,
        )
        .await;
        Outcome {
            code,
            stderr: String::from_utf8(stderr).unwrap(),
            envelope,
        }
    }

    fn policy_path(dir: &Path, name: &str) -> PathBuf {
        dir.join("policies").join(format!("{name}.toml"))
    }

    fn profile_path(dir: &Path, name: &str) -> PathBuf {
        dir.join("profiles").join(format!("{name}.toml"))
    }

    /// The body `init` writes for a USDC preset.
    fn usdc_body(name: &str, preset: &str, unlisted_budget: bool, total_budget: bool) -> String {
        let derived = presets::derive(&PresetInput {
            preset: presets::find_preset(preset).unwrap(),
            asset: PresetAsset::Usdc {
                issuer: USDC_MAINNET_ISSUER.to_owned(),
            },
            tolerated_loss_stroops: None,
            typical_payment_stroops: None,
            unlisted_budget,
            total_budget,
        })
        .unwrap();
        presets::policy_body(name, &derived)
    }

    /// Asserts that a refused run wrote neither the policy file nor the
    /// profile.
    fn assert_nothing_written(dir: &Path, name: &str) {
        assert!(!policy_path(dir, name).exists(), "policy file written");
        assert!(!profile_path(dir, name).exists(), "profile written");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn omitted_preset_flag_uses_api_day() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let dir = tempfile::tempdir().unwrap();
        let mut a = mainnet("preset-default");
        a.unlisted_budget = Some(YesNo::No);
        let out = init_at(&a, dir.path(), false, queue(&[])).await;
        assert_eq!(out.code, 0, "{}", out.envelope);
        assert_eq!(out.envelope["data"]["plan"]["preset"], "api-day");
        assert_eq!(
            std::fs::read_to_string(policy_path(dir.path(), "preset-default")).unwrap(),
            usdc_body("preset-default", "api-day", false, true)
        );
        assert!(profile_path(dir.path(), "preset-default").exists());
    }

    /// An api preset needs an explicit unlisted choice. Init refuses and
    /// writes nothing without a terminal, at end of input, after a read
    /// error, and for any answer but yes or no.
    #[tokio::test]
    #[serial_test::serial]
    async fn api_question_requires_explicit_choice() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let required = "the unlisted_budget input is required; pass --unlisted-budget, or run \
                        at a terminal to answer its prompt";
        let dir = tempfile::tempdir().unwrap();
        let a = mainnet("api-choice");
        let out = init_at(&a, dir.path(), false, queue(&["yes"])).await;
        assert_eq!(
            (out.code, out.error_code(), out.message()),
            (1, "profile.preset_input_required", required)
        );
        assert_eq!(out.stderr, "", "no prompt without a terminal");
        assert_nothing_written(dir.path(), "api-choice");

        let out = init_at(&a, dir.path(), true, queue(&[])).await;
        assert_eq!(
            (out.code, out.error_code(), out.message()),
            (1, "profile.preset_input_required", required)
        );
        assert!(out.stderr.starts_with("Allow payments"), "{}", out.stderr);
        assert_nothing_written(dir.path(), "api-choice");

        let failing = || std::future::ready(Err(io::Error::other("read refused")));
        let out = init_at(&a, dir.path(), true, failing).await;
        assert_eq!(
            (out.code, out.error_code(), out.message()),
            (1, "profile.preset_input_required", required)
        );
        assert_nothing_written(dir.path(), "api-choice");

        for answer in ["maybe", "y", ""] {
            let out = init_at(&a, dir.path(), true, queue(&[answer, ""])).await;
            assert_eq!(
                (out.code, out.error_code(), out.message()),
                (
                    1,
                    "profile.preset_invalid",
                    "the unlisted budget answer must be yes or no"
                ),
                "{answer:?}"
            );
            assert_nothing_written(dir.path(), "api-choice");
        }
    }

    /// The api question states the shared budget and its bounds, and a yes
    /// puts one budget on every payment rule.
    #[tokio::test]
    #[serial_test::serial]
    async fn api_question_states_shared_budget() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let dir = tempfile::tempdir().unwrap();
        let a = mainnet("api-shared");
        let out = init_at(&a, dir.path(), true, queue(&[" YES\r\n", "\r\n"])).await;
        assert_eq!(out.code, 0, "{}", out.envelope);
        assert!(
            out.stderr.starts_with(
                "Allow payments to unlisted recipients up to 0.5 USDC per rolling day, shared \
                 by all payment tools, at most 0.1 USDC per payment? [yes/no]: Limit total \
                 spending to 2 USDC"
            ),
            "{}",
            out.stderr
        );
        assert_eq!(
            std::fs::read_to_string(policy_path(dir.path(), "api-shared")).unwrap(),
            usdc_body("api-shared", "api-day", true, true)
        );
        let limits = &out.envelope["data"]["spending_summary"]["limits"][0];
        assert_eq!(
            limits["unlisted_mode"],
            serde_json::json!({"uniform": "budget"})
        );
        assert_eq!(
            limits["unlisted_tools"],
            serde_json::json!([
                "stellar_pay",
                "stellar_pay_commit",
                "stellar_x402_create_payment",
                "stellar_x402_authenticated_payment"
            ])
        );

        let mut a = mainnet("api-shared-week");
        a.preset = Some("api-week".to_owned());
        a.total_budget = Some(YesNo::Yes);
        let out = init_at(&a, dir.path(), true, queue(&["no"])).await;
        assert_eq!(out.code, 0, "{}", out.envelope);
        assert!(
            out.stderr.starts_with(
                "Allow payments to unlisted recipients up to 1.25 USDC per rolling day, shared \
                 by all payment tools, at most 0.25 USDC per payment? [yes/no]: {"
            ),
            "{}",
            out.stderr
        );
        assert_eq!(
            std::fs::read_to_string(policy_path(dir.path(), "api-shared-week")).unwrap(),
            usdc_body("api-shared-week", "api-week", false, true)
        );
    }

    /// The total budget question defaults to yes at a terminal, and without a
    /// terminal the total budget is chosen without a question.
    #[tokio::test]
    #[serial_test::serial]
    async fn total_budget_prompt_defaults_to_yes() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let question = "Limit total spending to 2 USDC for this policy? Signing the same policy \
                        body again keeps the allocation; a different digest starts another. \
                        [Y/n]: ";
        let dir = tempfile::tempdir().unwrap();
        for (n, (answer, total)) in [
            ("", true),
            ("\r\n", true),
            ("Y", true),
            ("yes", true),
            (" n \r\n", false),
            ("NO", false),
        ]
        .into_iter()
        .enumerate()
        {
            let name = format!("total-{n}");
            let mut a = mainnet(&name);
            a.unlisted_budget = Some(YesNo::No);
            let out = init_at(&a, dir.path(), true, queue(&[answer])).await;
            assert_eq!(out.code, 0, "{answer:?}: {}", out.envelope);
            assert!(out.stderr.starts_with(question), "{}", out.stderr);
            assert_eq!(
                std::fs::read_to_string(policy_path(dir.path(), &name)).unwrap(),
                usdc_body(&name, "api-day", false, total),
                "{answer:?}"
            );
        }

        let mut a = mainnet("total-other");
        a.unlisted_budget = Some(YesNo::No);
        let out = init_at(&a, dir.path(), true, queue(&["maybe"])).await;
        assert_eq!(
            (out.code, out.error_code(), out.message()),
            (
                1,
                "profile.preset_invalid",
                "the total budget answer must be y, yes, n, or no"
            )
        );
        assert_nothing_written(dir.path(), "total-other");

        let mut a = mainnet("total-unattended");
        a.unlisted_budget = Some(YesNo::No);
        let out = init_at(&a, dir.path(), false, queue(&["n"])).await;
        assert_eq!(out.code, 0, "{}", out.envelope);
        assert!(out.stderr.starts_with("{\"phase\""), "{}", out.stderr);
        assert_eq!(out.stderr.lines().count(), 1);
        assert_eq!(
            std::fs::read_to_string(policy_path(dir.path(), "total-unattended")).unwrap(),
            usdc_body("total-unattended", "api-day", false, true)
        );
    }

    /// XLM takes its amounts from the flags or, at a terminal, from the
    /// prompts in order; without a terminal a missing amount refuses.
    #[tokio::test]
    #[serial_test::serial]
    async fn xlm_inputs_from_flags_and_prompts() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let dir = tempfile::tempdir().unwrap();
        let xlm = |name: &str, loss: Option<&str>, typical: Option<&str>| {
            let mut a = mainnet(name);
            a.preset = Some("shop-day".to_owned());
            a.asset = Some(PresetAssetArg::Xlm);
            a.tolerated_loss = loss.map(str::to_owned);
            a.typical_payment = typical.map(str::to_owned);
            a.total_budget = Some(YesNo::Yes);
            a
        };
        let amounts = |out: &Outcome| {
            let plan = &out.envelope["data"]["plan"];
            (
                plan["asset"].as_str().unwrap().to_owned(),
                plan["tolerated_loss"].as_str().unwrap().to_owned(),
                plan["typical_payment"].as_str().unwrap().to_owned(),
            )
        };
        let expected = ("XLM".to_owned(), "10".to_owned(), "5".to_owned());

        let out = init_at(
            &xlm("xlm-flags", Some("10"), Some("5")),
            dir.path(),
            false,
            queue(&[]),
        )
        .await;
        assert_eq!(out.code, 0, "{}", out.envelope);
        assert_eq!(amounts(&out), expected);
        let body = std::fs::read_to_string(policy_path(dir.path(), "xlm-flags")).unwrap();
        assert!(body.contains("assets = [\"native\"]"), "{body}");

        let out = init_at(
            &xlm("xlm-prompts", None, None),
            dir.path(),
            true,
            queue(&["10\r\n", " 5\n"]),
        )
        .await;
        assert_eq!(out.code, 0, "{}", out.envelope);
        assert_eq!(amounts(&out), expected);
        assert!(
            out.stderr
                .starts_with("Tolerated loss in XLM: Typical payment in XLM: {"),
            "{}",
            out.stderr
        );

        let out = init_at(
            &xlm("xlm-mixed", Some("10"), None),
            dir.path(),
            true,
            queue(&["5"]),
        )
        .await;
        assert_eq!(out.code, 0, "{}", out.envelope);
        assert_eq!(amounts(&out), expected);
        assert!(
            out.stderr.starts_with("Typical payment in XLM: {"),
            "{}",
            out.stderr
        );

        let out = init_at(
            &xlm("xlm-missing", None, Some("5")),
            dir.path(),
            false,
            queue(&["10"]),
        )
        .await;
        assert_eq!(
            (out.code, out.error_code(), out.message()),
            (
                1,
                "profile.preset_input_required",
                "the tolerated_loss input is required; pass --tolerated-loss, or run at a \
                 terminal to answer its prompt"
            )
        );
        assert_nothing_written(dir.path(), "xlm-missing");

        let out = init_at(
            &xlm("xlm-malformed", None, None),
            dir.path(),
            true,
            queue(&["1,5"]),
        )
        .await;
        assert_eq!((out.code, out.error_code()), (1, "profile.preset_invalid"));
        assert_nothing_written(dir.path(), "xlm-malformed");
    }

    /// Flag combinations the preset refuses fail before any prompt and
    /// write nothing.
    #[tokio::test]
    #[serial_test::serial]
    async fn preset_flag_combinations_refuse() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let dir = tempfile::tempdir().unwrap();
        let mut compute = mainnet("combo-compute");
        compute.preset = Some("compute-week".to_owned());
        compute.unlisted_budget = Some(YesNo::Yes);
        let mut usdc_amount = mainnet("combo-usdc");
        usdc_amount.tolerated_loss = Some("5".to_owned());
        usdc_amount.unlisted_budget = Some(YesNo::No);
        let mut unknown = mainnet("combo-unknown");
        unknown.preset = Some("api-month".to_owned());
        let mut malformed = mainnet("combo-malformed");
        malformed.asset = Some(PresetAssetArg::Xlm);
        malformed.tolerated_loss = Some("-1".to_owned());
        for (a, message) in [
            (
                &compute,
                "an unlisted budget applies to api presets only, not compute-week",
            ),
            (
                &usdc_amount,
                "a USDC preset fixes its tolerated loss and typical payment; these inputs apply \
                 to XLM only",
            ),
            (&unknown, "unknown preset api-month; presets: "),
            (&malformed, "amount \"-1\" must be a decimal number"),
        ] {
            let name = a.profile.clone().unwrap();
            let out = init_at(a, dir.path(), true, queue(&["yes", "yes", "yes"])).await;
            assert_eq!(
                (out.code, out.error_code()),
                (1, "profile.preset_invalid"),
                "{name}"
            );
            assert!(
                out.message().starts_with(message),
                "{name}: {}",
                out.message()
            );
            assert_eq!(out.stderr, "", "{name}: no prompt");
            assert_nothing_written(dir.path(), &name);
        }
    }

    /// The spending flags and `--output` refuse outside mainnet V1, after
    /// the existing refusals, naming the flags in help order and never their
    /// values.
    #[tokio::test]
    #[serial_test::serial]
    async fn spending_flags_outside_mainnet_v1_refuse() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let dir = tempfile::tempdir().unwrap();
        let mut testnet = args("flags-testnet");
        testnet.preset = Some("MARKER-VALUE".to_owned());
        let mut every = args("flags-every");
        every.output = Some(OutputFormat::Table);
        every.total_budget = Some(YesNo::No);
        every.unlisted_budget = Some(YesNo::Yes);
        every.typical_payment = Some("MARKER-VALUE".to_owned());
        every.tolerated_loss = Some("MARKER-VALUE".to_owned());
        every.asset = Some(PresetAssetArg::Xlm);
        every.preset = Some("MARKER-VALUE".to_owned());
        let mut noop = mainnet("flags-noop");
        noop.engine = PolicyEngineKind::Noop;
        noop.output = Some(OutputFormat::Json);
        for (a, flags) in [
            (&testnet, "--preset"),
            (
                &every,
                "--preset, --asset, --tolerated-loss, --typical-payment, --unlisted-budget, \
                 --total-budget, --output",
            ),
            (&noop, "--output"),
        ] {
            let name = a.profile.clone().unwrap();
            let out = init_at(a, dir.path(), false, queue(&[])).await;
            assert_eq!(
                (out.code, out.error_code(), out.message().to_owned()),
                (
                    1,
                    "validation.usage_error",
                    format!("{flags}: these flags apply only to --network mainnet --engine v1")
                ),
                "{name}"
            );
            assert!(!out.envelope.to_string().contains("MARKER"), "{name}");
            assert_eq!(out.stderr, "");
            assert_nothing_written(dir.path(), &name);
        }

        // An existing profile refuses first.
        std::fs::create_dir_all(dir.path().join("profiles")).unwrap();
        std::fs::write(profile_path(dir.path(), "flags-testnet"), "version = 2\n").unwrap();
        let out = init_at(&testnet, dir.path(), false, queue(&[])).await;
        assert_eq!(
            (out.code, out.error_code()),
            (1, "validation.profile_already_exists")
        );

        // Without the flags, testnet and noop write no policy and carry no
        // preview, summary, or plan.
        for a in [args("plain-testnet"), {
            let mut a = mainnet("plain-noop");
            a.engine = PolicyEngineKind::Noop;
            a
        }] {
            let name = a.profile.clone().unwrap();
            let out = init_at(&a, dir.path(), true, queue(&[])).await;
            assert_eq!(out.code, 0, "{}", out.envelope);
            assert_eq!(out.stderr, "");
            assert!(!policy_path(dir.path(), &name).exists());
            let data = out.envelope["data"].as_object().unwrap();
            assert!(!data.contains_key("spending_summary") && !data.contains_key("plan"));
        }
    }

    /// The envelope carries the draft summary and the plan, equal to the
    /// preview on stderr; `--output table` writes the table form there.
    #[tokio::test]
    #[serial_test::serial]
    async fn mainnet_init_envelope_carries_summary_and_plan() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let dir = tempfile::tempdir().unwrap();
        let mut a = mainnet("envelope");
        a.unlisted_budget = Some(YesNo::Yes);
        let out = init_at(&a, dir.path(), false, queue(&[])).await;
        assert_eq!(out.code, 0, "{}", out.envelope);
        let data = &out.envelope["data"];
        assert_eq!(data["spending_summary"]["authority_status"], "draft");
        assert_eq!(data["plan"]["preset"], "api-day");
        assert_eq!(data["plan"]["recommended_balance_xlm"], "2");
        let preview = out.preview();
        assert_eq!(preview["phase"], "before_write");
        assert_eq!(preview["spending_summary"], data["spending_summary"]);
        assert_eq!(preview["plan"], data["plan"]);

        let mut a = mainnet("envelope-table");
        a.unlisted_budget = Some(YesNo::No);
        a.output = Some(OutputFormat::Table);
        let out = init_at(&a, dir.path(), false, queue(&[])).await;
        assert_eq!(out.code, 0, "{}", out.envelope);
        assert!(
            out.stderr
                .starts_with("phase: before_write\nSpending summary\nauthority_status: draft\n"),
            "{}",
            out.stderr
        );
        assert!(
            out.stderr.contains("\nPlan\npreset: api-day\n"),
            "{}",
            out.stderr
        );
        assert!(
            out.stderr.contains("\nFloor M: 1.7 XLM\n"),
            "{}",
            out.stderr
        );
        assert_eq!(out.envelope["data"]["plan"]["preset"], "api-day");
    }

    /// The summary `init` previews equals, field by field, the summary of
    /// the bytes `sign-policy` signs from the written file. Signing assigns
    /// the next sequence, so that field is one past the written body's.
    #[tokio::test]
    #[serial_test::serial]
    async fn init_preview_summarizes_the_signed_body() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let dir = tempfile::tempdir().unwrap();
        let mut a = mainnet("signed");
        a.unlisted_budget = Some(YesNo::Yes);
        let out = init_at(&a, dir.path(), false, queue(&[])).await;
        assert_eq!(out.code, 0, "{}", out.envelope);
        let written = std::fs::read_to_string(policy_path(dir.path(), "signed")).unwrap();
        let profile = load_from_dir("signed", &dir.path().join("profiles"), None).unwrap();
        let signed = super::super::sign_policy::prepare_policy(
            &written,
            &profile,
            "signed",
            &policy_path(dir.path(), "signed"),
            &dir.path().join("state.window"),
        )
        .unwrap();
        let summary = serde_json::to_value(presets::summarize(
            &signed.raw.parse::<toml_edit::DocumentMut>().unwrap(),
            MAINNET_PASSPHRASE,
            AuthorityStatus::Draft,
        ))
        .unwrap();
        let preview = out.preview();
        let shown = preview["spending_summary"].as_object().unwrap();
        let summary = summary.as_object().unwrap();
        assert_eq!(
            shown.keys().collect::<Vec<_>>(),
            summary.keys().collect::<Vec<_>>()
        );
        for (field, value) in summary {
            if field == "sequence" {
                assert_eq!(
                    (&shown[field], value),
                    (&serde_json::json!(1), &serde_json::json!(2))
                );
            } else {
                assert_eq!(&shown[field], value, "{field}");
            }
        }
        // Apart from the sequence line the signed body is the written one.
        assert_eq!(
            signed.raw.replacen("sequence = 2", "sequence = 1", 1),
            written
        );
    }

    /// A stderr writer that records, at each write and flush, whether the
    /// policy file and the profile exist.
    struct Observer {
        policy: PathBuf,
        profile: PathBuf,
        seen: Vec<(bool, bool)>,
        bytes: Vec<u8>,
    }

    impl Write for Observer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.seen
                .push((self.policy.exists(), self.profile.exists()));
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.seen
                .push((self.policy.exists(), self.profile.exists()));
            Ok(())
        }
    }

    /// Every prompt and the whole preview reach stderr before the policy
    /// file and the profile exist.
    #[tokio::test]
    #[serial_test::serial]
    async fn preview_precedes_every_write() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let dir = tempfile::tempdir().unwrap();
        let a = mainnet("observed");
        let mut observer = Observer {
            policy: policy_path(dir.path(), "observed"),
            profile: profile_path(dir.path(), "observed"),
            seen: Vec::new(),
            bytes: Vec::new(),
        };
        let (code, envelope) = init_into(
            &a,
            (&dir.path().join("profiles"), &dir.path().join("policies")),
            true,
            &mut observer,
            queue(&["no", ""]),
        )
        .await;
        assert_eq!(code, 0, "{envelope}");
        assert!(observer.policy.exists() && observer.profile.exists());
        assert!(observer.seen.len() >= 5, "{:?}", observer.seen);
        assert!(
            observer.seen.iter().all(|seen| *seen == (false, false)),
            "{:?}",
            observer.seen
        );
        let text = String::from_utf8(observer.bytes).unwrap();
        // The answers end the prompt lines at a terminal; the captured
        // stderr holds the prompts and then the preview line.
        let (prompts, preview) = text
            .split_once("{\"phase\"")
            .expect("the preview follows the prompts");
        assert!(prompts.starts_with("Allow payments to unlisted recipients"));
        assert!(prompts.ends_with("[Y/n]: "), "{prompts}");
        let preview: serde_json::Value =
            serde_json::from_str(&format!("{{\"phase\"{preview}")).unwrap();
        assert_eq!(preview["phase"], "before_write");
        assert!(preview["spending_summary"].is_object());
        assert!(preview["plan"].is_object());
    }

    /// A preview that cannot be written refuses with its code, and nothing
    /// is written.
    #[tokio::test]
    #[serial_test::serial]
    async fn preview_output_failure_prevents_write() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        for (n, writer) in [render::FailingWriter::Write, render::FailingWriter::Flush]
            .into_iter()
            .enumerate()
        {
            let dir = tempfile::tempdir().unwrap();
            let name = format!("unwritable-{n}");
            let mut a = mainnet(&name);
            a.unlisted_budget = Some(YesNo::No);
            let mut out = writer;
            let (code, envelope) = init_into(
                &a,
                (&dir.path().join("profiles"), &dir.path().join("policies")),
                false,
                &mut out,
                queue(&[]),
            )
            .await;
            assert_eq!(code, 1);
            assert_eq!(
                envelope["error"]["code"],
                "profile.spending_preview_unwritable"
            );
            assert!(envelope["error"]["details"].is_null(), "{envelope}");
            assert_nothing_written(dir.path(), &name);
        }
    }

    /// The policy file is written before the profile: when the profile
    /// cannot be written, the policy file exists and the refusal carries the
    /// preview.
    #[tokio::test]
    #[serial_test::serial]
    async fn policy_written_before_profile() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("profiles"), "a regular file").unwrap();
        let mut a = mainnet("ordered");
        a.unlisted_budget = Some(YesNo::No);
        let out = init_at(&a, dir.path(), false, queue(&[])).await;
        assert_eq!(
            (out.code, out.error_code()),
            (1, "internal.unexpected_state")
        );
        assert!(
            out.message()
                .starts_with("unexpected internal state: failed to write the profile: "),
            "{}",
            out.message()
        );
        assert_eq!(
            std::fs::read_to_string(policy_path(dir.path(), "ordered")).unwrap(),
            usdc_body("ordered", "api-day", false, true)
        );
        assert_eq!(
            out.envelope["error"]["details"]["preview"]["phase"],
            "before_write"
        );
        assert_eq!(out.envelope["error"]["details"]["preview"], out.preview());
    }

    /// A rerun after a failed profile write finds its own policy file and
    /// continues.
    #[tokio::test]
    #[serial_test::serial]
    async fn rerun_with_identical_policy_continues() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let dir = tempfile::tempdir().unwrap();
        let policies = dir.path().join("policies");
        let mut a = mainnet("rerun");
        a.unlisted_budget = Some(YesNo::No);
        for profiles in ["first", "second"] {
            let (code, envelope) = init_into(
                &a,
                (&dir.path().join(profiles), &policies),
                false,
                &mut Vec::new(),
                queue(&[]),
            )
            .await;
            assert_eq!(code, 0, "{profiles}: {envelope}");
            assert!(dir.path().join(profiles).join("rerun.toml").exists());
        }
        assert_eq!(
            std::fs::read_to_string(policy_path(dir.path(), "rerun")).unwrap(),
            usdc_body("rerun", "api-day", false, true)
        );
    }

    /// A policy file of other content, or one that cannot be written,
    /// refuses with the preview, leaves the file, and writes no profile.
    #[tokio::test]
    #[serial_test::serial]
    async fn rerun_with_other_policy_refuses() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let dir = tempfile::tempdir().unwrap();
        let path = policy_path(dir.path(), "other");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "version = 2\n# authored\n").unwrap();
        let mut a = mainnet("other");
        a.unlisted_budget = Some(YesNo::No);
        let out = init_at(&a, dir.path(), false, queue(&[])).await;
        assert_eq!(
            (out.code, out.error_code(), out.message().to_owned()),
            (
                1,
                "profile.policy_already_exists",
                format!(
                    "the policy file {} holds other content; the profile was not written",
                    path.display()
                )
            )
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "version = 2\n# authored\n"
        );
        assert!(!profile_path(dir.path(), "other").exists());
        assert_eq!(out.envelope["error"]["details"]["preview"], out.preview());

        let blocked = tempfile::tempdir().unwrap();
        std::fs::write(blocked.path().join("policies"), "a regular file").unwrap();
        let out = init_at(&a, blocked.path(), false, queue(&[])).await;
        assert_eq!(
            (out.code, out.error_code()),
            (1, "profile.preset_write_failed")
        );
        assert!(
            out.message().ends_with("; the profile was not written"),
            "{}",
            out.message()
        );
        assert!(!profile_path(blocked.path(), "other").exists());
        assert_eq!(out.envelope["error"]["details"]["preview"], out.preview());
    }

    /// A mainnet V1 profile reviews the generated version 2 body; testnet
    /// creates a version 1 file.
    #[test]
    fn next_steps_for_mainnet_v1_require_policy_body_version_2() {
        let steps = next_steps("alpha", PolicyEngineKind::V1, TargetNetwork::Mainnet);
        assert_eq!(steps.len(), 9, "{steps:#?}");
        for marker in [
            "policies/alpha.toml",
            "`version = 2`",
            "Set up mainnet writes",
        ] {
            assert!(steps[5].contains(marker), "{marker}: {}", steps[5]);
        }
        let testnet = next_steps("alpha", PolicyEngineKind::V1, TargetNetwork::Testnet);
        assert!(testnet[5].contains("`version = 1`"), "{}", testnet[5]);
    }
}
