//! `stellar-agent smart-account multicall` subcommand.
//!
//! Submits an atomic multicall bundle via the registered multicall router
//! contract on the target network. The bundle is specified as one or more
//! `--invocation '<target>:<fn>:<json-args>'` flags (1 ≤ count ≤
//! `MULTICALL_BUNDLE_CAP=50`).
//!
//! # Flags
//!
//! | Flag | Required | Description |
//! |------|----------|-------------|
//! | `--invocation '<target>:<fn>:<json-args>'` | yes (1+) | Invocation descriptor. Repeatable. |
//! | `--smart-account <C_STRKEY>` | yes | Smart-account contract address. |
//! | `--rule-id <U32>` | yes | Context-rule ID under which the bundle is authorised. |
//! | `--secondary-rpc-url <URL>` | see below | Secondary RPC for 4-way trust-anchor equality. |
//! | `--network` | no | `testnet` (default) or `mainnet`. |
//! | `--rpc-url <URL>` | no | Primary Soroban RPC endpoint. |
//! | `--timeout-seconds <N>` | no | Submission timeout in seconds (default 60). |
//! | `--fee <STROOPS>` | no | Per-op base fee (default 100 stroops). |
//! | Signer-source flags | yes | One of: `--signer-secret-env`, `--sign-with-ledger`. |
//! | `--profile <NAME>` | no | Profile name (default `"default"`). |
//!
//! # Secondary RPC resolution
//!
//! The secondary RPC URL is resolved in priority order:
//!
//! 1. `profile.secondary_rpc_url` from the loaded profile TOML.
//! 2. `--secondary-rpc-url` CLI flag (overrides the profile field).
//! 3. If neither is set: error with `WalletError::Auth` typed error.
//!
//! # Invocation format
//!
//! Each `--invocation` value MUST have the form `<target>:<fn>:<json-args>`:
//! - `<target>` — C-strkey of the target contract.
//! - `<fn>` — Soroban function name (≤32 bytes, no special characters).
//! - `<json-args>` — JSON array of arguments.
//!
//! Parse errors at the CLI layer surface as `MulticallInvocation` candidates
//! with sentinel error fields; `submit_multicall_bundle` Step 1 (build) validates
//! all fields and refuses with `SaMulticallBundleDenied { refusal_phase: "build" }`.
//!
//! # Output
//!
//! JSON envelope on stdout. On success: `{ "bundle_tx_hash": "...", "inner_count": N,
//! "ledger": N, "inner_results": [...], "audit_degraded": false }`. On error: typed
//! wire-code envelope.
//!
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{ArgGroup, Args};
use serde::{Deserialize, Serialize};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{AuthError, IoSource, ValidationError, WalletError};
use stellar_agent_core::policy::v1::PolicyEngineV1;
use stellar_agent_network::{ClassicFeeChoice, parse_classic_fee_choice};
use stellar_agent_smart_account::ResolvedFeePerOp;
use stellar_agent_smart_account::multicall::{
    MULTICALL_BUNDLE_CAP, MulticallInvocation, MulticallRegistry, MulticallSubmitArgs,
    STELLAR_AGENT_MULTICALL_REGISTRY_TOML_ENV, submit_multicall_bundle,
};
use tracing::warn;
use uuid::Uuid;

use crate::commands::smart_account::common::{
    SignerSourceFlags, emit_multicall_registry_error, emit_sa_error, network_to_chain_id,
    open_audit_writer,
};
use crate::common::network::TargetNetwork;
use crate::common::render::render_json;
use crate::common::resolve_profile_name;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default submission timeout in seconds.
const DEFAULT_TIMEOUT_SECONDS: u64 = 60;

/// Default per-op base fee in stroops.
const DEFAULT_FEE_STROOPS: u32 = 100;

/// Default Stellar testnet Soroban RPC endpoint.
const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";

// ─────────────────────────────────────────────────────────────────────────────
// CLI Args
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account multicall`.
///
/// Submits an atomic multicall bundle via the registered multicall router on
/// the target network.
#[non_exhaustive]
#[derive(Debug, Args)]
#[command(
    name = "multicall",
    group(
        ArgGroup::new("signer_source")
            .args(["signer_secret_env", "sign_with_ledger"])
            .required(true)
    )
)]
pub struct MulticallArgs {
    /// C-strkey of the smart-account contract executing the multicall.
    #[arg(long, value_name = "C_STRKEY")]
    pub smart_account: String,

    /// Context-rule ID under which the bundle is authorised.
    #[arg(long, value_name = "U32")]
    pub rule_id: u32,

    /// Invocation descriptor: `<target_c_strkey>:<fn_name>:<json_args_array>`.
    ///
    /// Repeatable (1–50 invocations). Each value MUST have the form:
    /// `<target>:<fn>:<json-args>` where `<json-args>` is a JSON array.
    ///
    /// Examples:
    /// - `CABC...WXYZ:transfer:["GABC...","GWXYZ...","1000000"]`
    ///
    /// Parse errors surface at Step 1 (build validation) of `submit_multicall_bundle`.
    #[arg(
        long,
        value_name = "TARGET:FN:JSON_ARGS",
        num_args = 1..,
        required = true,
    )]
    pub invocation: Vec<String>,

    /// Secondary Soroban RPC URL for 4-way trust-anchor cross-verification.
    ///
    /// Resolution priority: `profile.secondary_rpc_url` (from profile TOML) →
    /// this flag (overrides profile) → typed error when neither is set.
    #[arg(long, value_name = "URL")]
    pub secondary_rpc_url: Option<String>,

    /// Network to target. Only `testnet` is currently operational for multicall.
    ///
    /// Mainnet is accepted at the flag level but requires a deployed and registered
    /// multicall router on mainnet and a matching `MULTICALL_WASM_SHA256` binary const.
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Primary Soroban RPC endpoint URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Submission timeout in seconds (default 60).
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,

    /// Per-op base fee in stroops. `auto[:pNN]` is rejected during CLI parsing.
    #[arg(
        long,
        value_name = "STROOPS",
        value_parser = parse_multicall_fee_choice,
    )]
    pub fee: Option<ClassicFeeChoice>,

    /// Profile name (default `"default"`).
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    // ── Signer-source flags (exactly one required) ──────────────────────────
    /// S-strkey environment variable holding the signing key.
    #[arg(long, value_name = "VAR", group = "signer_source")]
    pub signer_secret_env: Option<String>,

    /// Use a Ledger hardware-wallet signer.
    #[arg(long, group = "signer_source")]
    pub sign_with_ledger: bool,

    /// BIP-44 account index for Ledger derivation (default 0).
    #[arg(long, default_value_t = 0_u32, value_name = "INDEX")]
    pub account_index: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Output types
// ─────────────────────────────────────────────────────────────────────────────

/// JSON envelope payload for a successful multicall bundle submission.
///
/// Serialised to stdout as deterministic JSON output.
#[derive(Debug, Serialize, Deserialize)]
pub struct MulticallOutput {
    /// Transaction hash of the confirmed bundle (first-8-last-8 redacted).
    pub bundle_tx_hash: String,
    /// Ledger sequence at which the bundle was confirmed.
    pub ledger: u32,
    /// Number of inner invocations in the confirmed bundle.
    pub inner_count: u32,
    /// Per-inner result summaries.
    pub inner_results: Vec<InnerResultOutput>,
    /// `true` when the bundle landed on-chain but audit emission failed post-submit.
    pub audit_degraded: bool,
}

/// Per-inner result summary in the multicall output envelope.
#[derive(Debug, Serialize, Deserialize)]
pub struct InnerResultOutput {
    /// Zero-based index of this inner within the bundle.
    pub inner_index: u32,
    /// Target contract C-strkey (redacted first-5-last-5).
    pub target_contract: String,
    /// Soroban function name that was called.
    pub fn_name: String,
    /// Base64-encoded `ScVal` return value, or empty string for `Void`.
    pub return_scval_b64: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// run — main dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Runs the `smart-account multicall` subcommand.
///
/// Validates inputs, resolves signer and secondary RPC, loads the multicall
/// registry, then delegates to `submit_multicall_bundle`. Renders the result
/// as a JSON envelope on stdout.
///
/// Returns an exit code: `0` on success, `1` on any error.
///
/// # Errors
///
/// Never returns `Err` — all errors are captured into the envelope and exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &MulticallArgs) -> i32 {
    // Validate bundle cardinality before anything else.
    if args.invocation.is_empty() {
        let err = WalletError::Validation(ValidationError::BundleEmpty);
        render_json(&Envelope::<()>::err(&err));
        return 1;
    }
    if args.invocation.len() > MULTICALL_BUNDLE_CAP as usize {
        let err = WalletError::Validation(ValidationError::BundleTooLarge {
            got: args.invocation.len(),
            max: MULTICALL_BUNDLE_CAP,
        });
        render_json(&Envelope::<()>::err(&err));
        return 1;
    }

    // Resolve signer.
    let signer = {
        let signer_flags = SignerSourceFlags {
            signer_secret_env: args.signer_secret_env.clone(),
            sign_with_ledger: args.sign_with_ledger,
            account_index: Some(args.account_index),
        };
        match resolve_signer(&signer_flags).await {
            Ok(s) => s,
            Err(e) => {
                render_json(&Envelope::<()>::err(&e));
                return 1;
            }
        }
    };

    let profile_name = resolve_profile_name(args.profile.as_deref());
    let network_passphrase = args.network.passphrase().to_owned();
    let chain_id = network_to_chain_id(args.network).to_owned();

    // Load the multicall registry.
    let networks_toml_path = resolve_networks_toml_path();
    let registry = match MulticallRegistry::load(&networks_toml_path) {
        Ok(r) => {
            if !r.partial_load_warnings.is_empty() {
                warn!(
                    "multicall registry loaded with {} partial-load warning(s); \
                     entries with invalid strkeys or SHA-256 hex will not be usable",
                    r.partial_load_warnings.len()
                );
            }
            r
        }
        Err(e) => {
            return emit_multicall_registry_error(&e, IoSource::MulticallRegistryLoad);
        }
    };

    // Resolve secondary_rpc_url:
    // Priority: profile.secondary_rpc_url → --secondary-rpc-url flag → typed error.
    let secondary_rpc_url = {
        // Try loading the profile to get secondary_rpc_url from it.
        // Distinguish NotFound (first-run or no profile — acceptable fall-through) from
        // other variants (e.g. VersionUnsupported, MissingPolicySection — warn but still
        // fall through to the flag, since multicall does not hard-require the profile).
        // Non-NotFound ProfileLoadError is not silently swallowed; it is logged.
        let from_profile = match stellar_agent_core::profile::loader::load(
            &profile_name,
            Some(&registry),
        ) {
            Ok(p) => p.secondary_rpc_url,
            Err(stellar_agent_core::profile::loader::ProfileLoadError::NotFound { .. }) => None,
            Err(e) => {
                warn!(
                    profile_name = %profile_name,
                    error = %e,
                    "smart-account multicall: non-fatal profile load error (secondary_rpc_url not \
                     available from profile; use --secondary-rpc-url flag to supply it)"
                );
                None
            }
        };

        match (from_profile, args.secondary_rpc_url.as_deref()) {
            // Flag overrides profile.
            (_, Some(flag_url)) => flag_url.to_owned(),
            // Profile provides the URL.
            (Some(profile_url), None) => profile_url,
            // Neither set.
            (None, None) => {
                let err = WalletError::Validation(ValidationError::AddressInvalid {
                    input: "secondary_rpc_url is required for multicall: set it in the profile \
                            TOML (secondary_rpc_url = \"https://...\") or pass \
                            --secondary-rpc-url"
                        .to_owned(),
                });
                render_json(&Envelope::<()>::err(&err));
                return 1;
            }
        }
    };

    // Parse the fee.
    let fee = match resolve_multicall_fee(args.fee.as_ref()) {
        Ok(fee) => fee,
        Err(e) => {
            render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };

    // Parse invocations. CLI-side parsing errors produce MulticallInvocation
    // values with sentinel data; Step 1 (build) validation in submit_multicall_bundle
    // will refuse them with SaMulticallBundleDenied { refusal_phase: "build" }.
    let bundle = parse_invocations(&args.invocation);

    // Open audit writer (non-fatal: missing profile dir or first-run are expected).
    let audit_writer = open_audit_writer(&profile_name).map(|(w, _)| w).ok();

    // Load policy engine.
    let policy_engine = match load_policy_engine_for_profile(&profile_name) {
        Ok(pe) => pe,
        Err(e) => {
            render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };

    // Build a minimal profile for policy evaluation.
    let profile = build_minimal_profile(args.network, secondary_rpc_url.clone());

    let request_id = Uuid::new_v4().to_string();

    let submit_args = MulticallSubmitArgs {
        smart_account: &args.smart_account,
        rule_id: args.rule_id,
        bundle,
        signer: signer.as_ref(),
        primary_rpc_url: &args.rpc_url,
        secondary_rpc_url: &secondary_rpc_url,
        network_passphrase: &network_passphrase,
        policy_engine,
        profile: &profile,
        audit_writer: audit_writer.as_ref().map(Arc::clone),
        timeout: Duration::from_secs(args.timeout_seconds),
        fee,
        chain_id: &chain_id,
        request_id: &request_id,
    };

    match submit_multicall_bundle(submit_args, &registry).await {
        Ok(result) => {
            let output = MulticallOutput {
                bundle_tx_hash: result.bundle_tx_hash,
                ledger: result.ledger,
                inner_count: result.inner_count,
                inner_results: result
                    .inner_results
                    .into_iter()
                    .map(|ir| InnerResultOutput {
                        inner_index: ir.inner_index,
                        target_contract: ir.target_contract,
                        fn_name: ir.fn_name,
                        return_scval_b64: ir.return_scval_b64,
                    })
                    .collect(),
                audit_degraded: result.audit_degraded,
            };
            render_json(&Envelope::ok(output));
            0
        }
        Err(e) => emit_sa_error(&e),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Parses `--invocation` flag values into [`MulticallInvocation`] instances.
///
/// Format: `<target_c_strkey>:<fn_name>:<json_args_array>`.
///
/// Parse failures produce invocations with sentinel error strings so that
/// Step 1 (build validation) of `submit_multicall_bundle` reports structured
/// denial rows rather than a raw parse error.
fn parse_invocations(raw: &[String]) -> Vec<MulticallInvocation> {
    raw.iter().map(|s| parse_single_invocation(s)).collect()
}

fn parse_multicall_fee_choice(raw: &str) -> Result<ClassicFeeChoice, String> {
    match parse_classic_fee_choice(Some(raw)).map_err(|e| e.to_string())? {
        ClassicFeeChoice::Auto(_) => Err(
            "auto[:pNN] fee resolution is not yet supported for multicall; pass an explicit <stroops> value"
                .to_owned(),
        ),
        choice => Ok(choice),
    }
}

fn resolve_multicall_fee(
    raw_fee: Option<&ClassicFeeChoice>,
) -> Result<ResolvedFeePerOp, WalletError> {
    let fee_stroops = match raw_fee {
        None => DEFAULT_FEE_STROOPS,
        Some(ClassicFeeChoice::Explicit(stroops)) => *stroops,
        Some(ClassicFeeChoice::ProfileDefault) => DEFAULT_FEE_STROOPS,
        Some(ClassicFeeChoice::Auto(_)) => {
            return Err(WalletError::Validation(
                ValidationError::UnsupportedFeeMode {
                    mode: "auto".to_owned(),
                    reason: "smart-account multicall rejects auto fee mode during CLI parsing"
                        .to_owned(),
                },
            ));
        }
    };

    Ok(ResolvedFeePerOp {
        base_stroops: fee_stroops,
    })
}

/// Parses a single `<target>:<fn>:<json-args>` invocation string.
///
/// On parse failure, returns a sentinel `MulticallInvocation` whose fields
/// encode the error. Step 1 of `submit_multicall_bundle` validates all three
/// fields and emits a `SaMulticallBundleDenied { refusal_phase: "build" }` row.
fn parse_single_invocation(raw: &str) -> MulticallInvocation {
    // Split on `:` with a max of 3 parts (json-args may contain colons).
    let parts: Vec<&str> = raw.splitn(3, ':').collect();
    if parts.len() != 3 {
        return MulticallInvocation {
            target_contract: format!("<parse_error: missing fields in {raw:?}>"),
            fn_name: String::new(),
            args_json: serde_json::Value::Null,
        };
    }

    let target_contract = parts[0].to_owned();
    let fn_name = parts[1].to_owned();
    let args_json = match serde_json::from_str::<serde_json::Value>(parts[2]) {
        Ok(v) => v,
        Err(e) => {
            return MulticallInvocation {
                target_contract,
                fn_name,
                args_json: serde_json::Value::String(format!(
                    "<parse_error: invalid JSON args: {e}>"
                )),
            };
        }
    };

    MulticallInvocation {
        target_contract,
        fn_name,
        args_json,
    }
}

/// Resolves the path to `networks.toml`, respecting the env-var override.
fn resolve_networks_toml_path() -> PathBuf {
    // Honour the same env-var override that MulticallRegistry::load uses.
    if let Ok(override_str) = std::env::var(STELLAR_AGENT_MULTICALL_REGISTRY_TOML_ENV)
        && !override_str.is_empty()
    {
        return PathBuf::from(override_str);
    }
    // OS-conventional default.
    directories::BaseDirs::new()
        .map(|b| b.config_dir().join("stellar-agent").join("networks.toml"))
        .unwrap_or_else(|| PathBuf::from("~/.config/stellar-agent/networks.toml"))
}

/// Constructs a permissive `PolicyEngineV1` for the CLI multicall path.
///
/// # Permissive-engine rationale
///
/// The CLI multicall path (`smart-account multicall`) bypasses profile-configured
/// policy. A permissive engine with no rules is correct here because the
/// operator is exercising **explicit intent** by running the binary directly.
/// Profile-configured policy applies only to **MCP-mediated** multicall
/// invocations, where the agent layer supplies the bundle and the MCP server
/// gates it through the signed policy document.
///
/// CLI multicall does not load a signed policy file by design — doing so would
/// require the CLI to know the policy document's signature key, which is a
/// concern of the MCP server's trust model, not the CLI's direct-operator model.
///
/// If you need policy enforcement on CLI multicall, use the MCP server interface.
///
/// # Errors
///
/// Never returns `Err` (infallible for the permissive-engine path).
fn load_policy_engine_for_profile(profile_name: &str) -> Result<Arc<PolicyEngineV1>, WalletError> {
    use stellar_agent_core::policy::v1::loader::{PolicyDocument, ScopeId};

    let doc = PolicyDocument {
        version: 1,
        scope: ScopeId::AllProfiles,
        rules: vec![],
        signature: None,
    };
    Ok(Arc::new(PolicyEngineV1::new(doc, profile_name.to_owned())))
}

/// Builds a minimal `Profile` for policy-engine evaluation.
///
/// Constructs a network-appropriate profile with `secondary_rpc_url` set.
/// Only `chain_id`, `network_passphrase`, and `secondary_rpc_url` need to be
/// correct for `evaluate_bundle` in `submit_multicall_bundle`.
fn build_minimal_profile(
    network: crate::common::network::TargetNetwork,
    secondary_rpc_url: String,
) -> stellar_agent_core::profile::schema::Profile {
    use crate::common::network::TargetNetwork;
    use stellar_agent_core::profile::schema::Profile;
    match network {
        TargetNetwork::Testnet => Profile::builder_testnet(
            "stellar-agent-signer",
            "multicall-cli",
            "stellar-agent-nonce",
            "multicall-cli",
        )
        .secondary_rpc_url(Some(secondary_rpc_url))
        .build(),
        TargetNetwork::Mainnet => Profile::builder_mainnet(
            "stellar-agent-signer",
            "multicall-cli",
            "stellar-agent-nonce",
            "multicall-cli",
        )
        .secondary_rpc_url(Some(secondary_rpc_url))
        .build(),
    }
}

/// Resolves the signer from the two mutually-exclusive flag modes.
async fn resolve_signer(
    flags: &SignerSourceFlags,
) -> Result<Box<dyn stellar_agent_network::Signer + Send + Sync>, WalletError> {
    if flags.sign_with_ledger {
        use stellar_agent_network::signing::hardware::HardwareSigningKey;
        let hw_key = HardwareSigningKey::native()
            .map_err(|e| {
                WalletError::Auth(AuthError::KeyringNotFound {
                    name: format!("Ledger not found or Stellar app not open: {e}"),
                })
            })?
            .with_account_index(flags.account_index.unwrap_or(0));
        return Ok(Box::new(hw_key));
    }

    let var_name = flags.signer_secret_env.as_deref().ok_or_else(|| {
        WalletError::Auth(AuthError::KeyringNotFound {
            name: "no signer-source flag specified for smart-account multicall; \
                   pass --signer-secret-env <VAR> or --sign-with-ledger"
                .to_owned(),
        })
    })?;
    use zeroize::Zeroizing;
    let s_strkey: Zeroizing<String> = Zeroizing::new(std::env::var(var_name).map_err(|_| {
        WalletError::Auth(AuthError::KeyringNotFound {
            name: format!("environment variable '{var_name}' not set"),
        })
    })?);
    let private_key =
        stellar_strkey::ed25519::PrivateKey::from_string(&s_strkey).map_err(|_| {
            WalletError::Auth(AuthError::KeyringNotFound {
                name: format!("environment variable '{var_name}' contains an invalid S-strkey"),
            })
        })?;
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(private_key.0);
    Ok(Box::new(
        stellar_agent_network::SoftwareSigningKey::new_from_zeroizing(seed),
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test-only")]
    use super::*;

    #[test]
    fn parse_invocation_valid() {
        let raw = r#"CABC123:transfer:["GAAA","GBBB","1000000"]"#;
        let inv = parse_single_invocation(raw);
        assert_eq!(inv.target_contract, "CABC123");
        assert_eq!(inv.fn_name, "transfer");
        assert!(inv.args_json.is_array());
        assert_eq!(inv.args_json.as_array().unwrap().len(), 3);
    }

    #[test]
    fn parse_invocation_missing_fields() {
        let raw = "CABC123:transfer";
        let inv = parse_single_invocation(raw);
        // Target contract gets the error sentinel.
        assert!(
            inv.target_contract.starts_with("<parse_error:"),
            "expected sentinel: got {:?}",
            inv.target_contract
        );
    }

    #[test]
    fn parse_invocation_invalid_json() {
        let raw = "CABC123:transfer:not-json";
        let inv = parse_single_invocation(raw);
        // args_json is a String sentinel, not an array.
        assert!(
            matches!(&inv.args_json, serde_json::Value::String(s) if s.starts_with("<parse_error:")),
            "expected args_json sentinel, got: {:?}",
            inv.args_json
        );
    }

    #[test]
    fn parse_invocation_colon_in_json_args() {
        // JSON args may contain colons; splitn(3) must not eat them.
        let raw = r#"CABC123:invoke:{"key":"value:with:colons"}"#;
        let inv = parse_single_invocation(raw);
        assert_eq!(inv.target_contract, "CABC123");
        assert_eq!(inv.fn_name, "invoke");
        // Should be parsed as a JSON object, not array, but no sentinel.
        assert!(
            !matches!(&inv.args_json, serde_json::Value::String(s) if s.starts_with("<parse_error:"))
        );
    }

    #[test]
    fn parse_invocations_batch() {
        let raw = vec![
            r#"CABC123:transfer:["GAAA","GBBB","500"]"#.to_owned(),
            r#"CDEF456:mint:["GAAA","1000"]"#.to_owned(),
        ];
        let invs = parse_invocations(&raw);
        assert_eq!(invs.len(), 2);
        assert_eq!(invs[0].fn_name, "transfer");
        assert_eq!(invs[1].fn_name, "mint");
    }

    #[test]
    fn resolve_multicall_fee_accepts_explicit_stroops() {
        let fee = resolve_multicall_fee(Some(&ClassicFeeChoice::Explicit(250))).unwrap();
        assert_eq!(fee.base_stroops, 250);
    }

    #[test]
    fn parse_multicall_fee_rejects_auto_at_parse_time() {
        let err = parse_multicall_fee_choice("auto").unwrap_err();
        assert!(err.contains("not yet supported"));
    }
}
