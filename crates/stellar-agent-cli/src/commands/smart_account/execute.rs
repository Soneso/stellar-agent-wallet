//! `stellar-agent smart-account execute` — submit an External-Ed25519-signed
//! `CallContract` invocation against an external contract.
//!
//! Surfaces the library `submit_signed_invoke` +
//! [`Ed25519RuleSigner`] call shape as an operator-facing verb: an agent-held Ed25519 rule key
//! authorises one invocation against an external contract (e.g. a SEP-41
//! transfer), under a named context rule, with a separate fee-paying
//! envelope signer.
//!
//! # Signer roles
//!
//! Two distinct signers participate:
//!
//! - **Rule signer** (`--rule-signer-ed25519-secret-env`) — the agent's
//!   External-Ed25519 key that authorises the smart-account call. Raw
//!   ed25519 signs the 32-byte auth digest directly (no G-key sub-entry).
//!   Derived via the shared mlock-protected ceremony
//!   (`resolve_software_signer_from_env`); the funded-source check other
//!   secret-env signers get is skipped because a rule key has no on-chain
//!   account.
//! - **Fee-payer signer** (`--signer-secret-env` / `--sign-with-ledger`) —
//!   the funded source account that pays the transaction fee and signs the
//!   envelope. Standard [`crate::commands::smart_account::common::SignerSourceFlags`]
//!   convention.
//!
//! # `--auth-rule-id` deviation
//!
//! Unlike every other smart-account write verb, `--auth-rule-id` has NO
//! default here and is required. The delegation use case always names a
//! non-zero `CallContract` rule; a defaulted `[0]` would silently submit
//! against the bootstrap rule and fail on-chain with `NotAllowed` (3223)
//! instead of surfacing the caller's mistake up front.
//!
//! # Mainnet defence
//!
//! Structurally refused (`network.mainnet_write_forbidden`) before any RPC
//! call or key-material access.
//!
//! # Wire codes rendered
//!
//! On-chain `SaError::DeploymentFailed { phase: "simulate", .. }` failures
//! carry the OZ symbolic error name inline in `message` (e.g.
//! `[OZ:SpendingLimitExceeded]`, `[OZ:NotAllowed]`, `[OZ:UnvalidatedContext]`)
//! — the same annotation mechanism every sibling smart-account write verb
//! relies on (`augment_with_oz_error_name`, applied inside
//! `submit_signed_invoke` itself).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Args;
use serde::{Deserialize, Serialize};
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::SaInvocationResult;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{AuthError, NetworkError, ValidationError, WalletError};
use stellar_agent_core::observability::{RedactedStrkey, redact_strkey_first5_last5};
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_network::signing::Signer;
use stellar_agent_network::submit::redact_tx_hash;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::rules::parse_c_strkey_to_smart_account;
use stellar_agent_smart_account::submit::{
    Ed25519RuleSigner, SubmitInvokeArgs, submit_signed_invoke,
};
use stellar_agent_smart_account::verifiers::VerifierRegistry;
use stellar_xdr::{HostFunction, InvokeContractArgs, Limits, ReadXdr as _, ScSymbol, ScVal, VecM};
use tracing::info;
use uuid::Uuid;

use crate::commands::smart_account::common::{
    SignerSourceFlags, network_to_chain_id, open_audit_writer, resolve_signer, wrap_sa_error,
};
use crate::common::network::TargetNetwork;
use crate::common::render::{render_json, sanitize_for_table};
use crate::common::resolve_profile_name;
use crate::common::signer_ceremony::resolve_software_signer_from_env;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default submission timeout in seconds.
const DEFAULT_TIMEOUT_SECONDS: u64 = 60;

/// Default Stellar testnet Soroban RPC endpoint.
const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";

// ─────────────────────────────────────────────────────────────────────────────
// ExecuteArgs
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account execute`.
#[non_exhaustive]
#[derive(Debug, Args)]
pub struct ExecuteArgs {
    /// Smart-account C-strkey whose rule authorises the call (`auth_address`).
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub account: String,

    /// External target contract C-strkey (`target_contract`).
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub contract: String,

    /// Contract function to invoke.
    #[arg(long, value_name = "NAME", required = true)]
    pub function: String,

    /// Standard-base64 XDR `ScVal` argument. Repeatable; order preserved.
    ///
    /// Decoded client-side with a bounded XDR decode (depth 500, length
    /// bounded by the argument's own encoded length). The decoded `ScVal`
    /// itself builds the invocation and is canonically re-encoded at
    /// submission, so the value validated is exactly the value sent.
    #[arg(long = "arg", value_name = "SCVAL_BASE64",
          num_args = 1.., action = clap::ArgAction::Append)]
    pub arg: Vec<String>,

    /// Context rule id(s) whose signers authorise this call.
    ///
    /// REQUIRED — no default. Deviation from the codebase's default-`[0]`
    /// convention: the delegation use case always names a non-zero
    /// `CallContract` rule; a defaulted bootstrap rule would silently
    /// produce on-chain `NotAllowed` (3223) instead of surfacing the
    /// caller's mistake before submission. Repeatable.
    #[arg(long = "auth-rule-id", value_name = "U32", required = true,
          num_args = 1.., action = clap::ArgAction::Append)]
    pub auth_rule_id: Vec<u32>,

    /// Name of the environment variable holding the rule signer's Ed25519
    /// seed (S-strkey).
    ///
    /// This is the agent-held rule key that authorises the call — distinct
    /// from the fee-payer signer (`--signer-secret-env` /
    /// `--sign-with-ledger`). Uses the full mlock-protected ceremony; the
    /// funded-source check other secret-env signers get is skipped (a rule
    /// key has no on-chain account).
    #[arg(long, value_name = "VAR", required = true)]
    pub rule_signer_ed25519_secret_env: String,

    /// Fail closed BEFORE signing if the seed-derived public key differs
    /// from this 64-hex-character value.
    ///
    /// Surfaces a misconfigured `--rule-signer-ed25519-secret-env` client-side
    /// instead of as an on-chain `NotAllowed`.
    #[arg(long, value_name = "64_HEX")]
    pub expect_rule_signer: Option<String>,

    /// Ed25519-verifier contract C-strkey override.
    ///
    /// When omitted, resolves from the `VerifierRegistry`'s registered
    /// Ed25519 verifier for the target network (deploy one via
    /// `smart-account deploy-ed25519-verifier`).
    #[arg(long, value_name = "C_STRKEY")]
    pub verifier: Option<String>,

    /// Fee-payer signer-source mode and Ledger derivation index.
    ///
    /// The funded source account that pays the transaction fee and signs
    /// the envelope — distinct from the rule signer.
    #[command(flatten)]
    pub signer_source: SignerSourceFlags,

    /// Profile name for audit-log path resolution.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Network to target (testnet / mainnet).
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Soroban RPC endpoint URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Secondary RPC URL for two-RPC consultation.
    #[arg(long, value_name = "URL")]
    pub secondary_rpc_url: Option<String>,

    /// Submission timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,
}

// ─────────────────────────────────────────────────────────────────────────────
// ExecuteResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result envelope for `smart-account execute`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteResult {
    /// Always `"submitted"` on success.
    pub status: String,
    /// External target contract C-strkey.
    pub contract: String,
    /// Contract function invoked.
    pub function: String,
    /// Number of `ScVal` arguments passed.
    pub arg_count: u32,
    /// Context rule IDs that authorised the call.
    pub auth_rule_ids: Vec<u32>,
    /// First 8 hex characters of the rule signer's raw Ed25519 public key.
    pub rule_signer_pubkey_first8: String,
    /// Ed25519-verifier contract C-strkey used to authenticate the signer.
    pub verifier_address: String,
    /// Confirmed Stellar transaction hash (64-char hex).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// run
// ─────────────────────────────────────────────────────────────────────────────

/// Validated, ready-to-submit inputs produced by [`validate_execute_inputs`].
#[derive(Debug)]
struct ExecutePlan {
    /// The `InvokeContract` host function built from `--contract`,
    /// `--function`, and the decoded `--arg` values.
    host_function: HostFunction,
    /// The resolved Ed25519-verifier contract address.
    verifier_sc_addr: stellar_xdr::ScAddress,
    /// The resolved verifier C-strkey, echoed in the success envelope.
    verifier_c_strkey: String,
    /// Number of `--arg` values (audit + envelope reporting).
    arg_count: u32,
}

/// Validates every client-side precondition and resolves the verifier,
/// producing an [`ExecutePlan`] — before any RPC call, keyring access, or
/// secret-material read.
///
/// # Errors
///
/// - [`NetworkError::MainnetWriteForbidden`] — `--network mainnet` is
///   structurally refused (smart-account write convention).
/// - [`ValidationError::AddressInvalid`] — empty or non-symbol `--function`,
///   malformed C-strkeys, an unresolvable verifier (no `--verifier` and no
///   registry entry for the target network), or too many `--arg` values.
/// - [`ValidationError::XdrArgumentMalformed`] — an `--arg` value that does
///   not decode as bounded standard-base64 XDR `ScVal` (the failing index is
///   named).
fn validate_execute_inputs(args: &ExecuteArgs) -> Result<ExecutePlan, WalletError> {
    // ── Mainnet structural refusal — before any RPC or key access ──────────
    if args.network == TargetNetwork::Mainnet {
        return Err(WalletError::Network(NetworkError::MainnetWriteForbidden));
    }

    // ── Client-side refusals before any I/O ────────────────────────────────

    if args.function.trim().is_empty() {
        return Err(WalletError::Validation(ValidationError::AddressInvalid {
            input: "--function must not be empty".to_owned(),
        }));
    }

    // Decode each --arg from standard-base64 XDR to validate well-formedness.
    // Bounded decode (depth 500, length bounded by the argument's own encoded
    // length) guards against XDR-bomb resource exhaustion on untrusted input.
    // The decoded ScVal builds the invocation directly and is canonically
    // re-encoded at submission: the value validated is the value sent.
    let mut sc_args: Vec<ScVal> = Vec::with_capacity(args.arg.len());
    for (idx, raw) in args.arg.iter().enumerate() {
        match ScVal::from_xdr_base64(
            raw,
            Limits {
                depth: 500,
                len: raw.len(),
            },
        ) {
            Ok(v) => sc_args.push(v),
            Err(e) => {
                return Err(WalletError::Validation(
                    ValidationError::XdrArgumentMalformed {
                        arg: format!("arg[{idx}]"),
                        reason: format!("{e}"),
                    },
                ));
            }
        }
    }

    // Resolve the Ed25519-verifier address: --verifier override else the
    // VerifierRegistry's registered entry for the target network. Fail
    // closed, mirroring `signers add --signer-ed25519`'s pattern exactly.
    let network_passphrase = args.network.passphrase();
    let verifier_c_strkey = if let Some(explicit) = &args.verifier {
        explicit.clone()
    } else {
        let registry = VerifierRegistry::open().map_err(|e| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: format!("could not open verifier registry: {e}"),
            })
        })?;
        match registry.ed25519_verifier_for(network_passphrase) {
            Some(entry) => entry.address.clone(),
            None => {
                return Err(WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!(
                        "no Ed25519 verifier registered for network '{network_passphrase}'; \
                         run: smart-account deploy-ed25519-verifier (or pass --verifier)"
                    ),
                }));
            }
        }
    };
    let verifier_sc_addr = parse_c_strkey("--verifier", &verifier_c_strkey)?;

    // Parse the target contract and (pre-validate only) the smart-account
    // C-strkeys before any key material is touched.
    let contract_sc_addr = parse_c_strkey("--contract", &args.contract)?;
    parse_c_strkey("--account", &args.account)?;

    let function_name = ScSymbol::try_from(args.function.as_str()).map_err(|()| {
        WalletError::Validation(ValidationError::AddressInvalid {
            input: format!(
                "--function '{}' invalid: must be a valid Soroban symbol (<=32 bytes, \
                 alphanumeric/underscore)",
                args.function
            ),
        })
    })?;
    let arg_count = sc_args.len() as u32;
    let args_vecm: VecM<ScVal> = sc_args.try_into().map_err(|e| {
        WalletError::Validation(ValidationError::AddressInvalid {
            input: format!("too many --arg values: {e}"),
        })
    })?;
    let host_function = HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: contract_sc_addr,
        function_name,
        args: args_vecm,
    });

    Ok(ExecutePlan {
        host_function,
        verifier_sc_addr,
        verifier_c_strkey,
        arg_count,
    })
}

/// Runs `smart-account execute`.
///
/// Returns an exit code: `0` on success, `1` on any error.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &ExecuteArgs) -> i32 {
    let request_id = new_request_id();
    let account_redacted = redact_strkey_first5_last5(&args.account);

    // Client-side validation: mainnet refusal, function/arg well-formedness,
    // and fail-closed verifier resolution — all before any key material or
    // RPC access. Extracted so tests assert the typed refusal, not an exit
    // code.
    let plan = match validate_execute_inputs(args) {
        Ok(p) => p,
        Err(e) => return emit_error(&e, args.output, &request_id),
    };
    let ExecutePlan {
        host_function,
        verifier_sc_addr,
        verifier_c_strkey,
        arg_count,
    } = plan;
    let network_passphrase = args.network.passphrase();
    let profile_name = resolve_profile_name(args.profile.as_deref());

    // ── Rule-signer key ceremony (shared mlock ceremony) ─────────────────────
    // Funded-source verification is SKIPPED: a rule key has no on-chain
    // account.
    let rule_signer = match resolve_software_signer_from_env(
        &args.rule_signer_ed25519_secret_env,
        "smart-account-execute",
        Some(&profile_name),
    )
    .await
    {
        Ok(s) => s,
        Err(e) => return emit_error(&e, args.output, &request_id),
    };

    let rule_pubkey = match rule_signer.public_key().await {
        Ok(pk) => pk,
        Err(e) => {
            drop(rule_signer);
            return emit_error(&e, args.output, &request_id);
        }
    };
    let rule_pubkey_hex = hex::encode(rule_pubkey.0);
    let rule_pubkey_first8 = rule_pubkey_hex
        .get(..8)
        .unwrap_or(&rule_pubkey_hex)
        .to_owned();

    // Fail closed BEFORE signing if --expect-rule-signer is set and differs.
    if let Some(expected_hex) = &args.expect_rule_signer
        && expected_hex.to_lowercase() != rule_pubkey_hex
    {
        drop(rule_signer);
        return emit_error(
            &WalletError::Auth(AuthError::SignerKeyMismatch {
                expected: expected_hex.clone(),
                got: rule_pubkey_hex,
            }),
            args.output,
            &request_id,
        );
    }

    // ── Fee-payer signer ────────────────────────────────────────────────────
    let fee_payer_signer = match resolve_signer(&args.signer_source, Some(&profile_name)).await {
        Ok(s) => s,
        Err(e) => {
            drop(rule_signer);
            return emit_error(&e, args.output, &request_id);
        }
    };

    let chain_id = network_to_chain_id(args.network);
    let auth_rule_ids_display: Vec<u32> = args.auth_rule_id.clone();
    let auth_rule_ids: Vec<ContextRuleId> = args
        .auth_rule_id
        .iter()
        .map(|id| ContextRuleId::new(*id))
        .collect();

    let submit_result = submit_signed_invoke(
        SubmitInvokeArgs::builder()
            .target_contract(args.contract.as_str())
            .auth_address(args.account.as_str())
            .auth_rule_ids(&auth_rule_ids)
            .host_function(host_function)
            .signer(fee_payer_signer.as_ref())
            .ed25519_rule_signer(Ed25519RuleSigner {
                signer: &rule_signer,
                verifier: verifier_sc_addr,
            })
            .primary_rpc_url(&args.rpc_url)
            .maybe_secondary_rpc_url(args.secondary_rpc_url.as_deref())
            .network_passphrase(network_passphrase)
            .chain_id(chain_id)
            .timeout(Duration::from_secs(args.timeout_seconds))
            .op_label("execute")
            .emit_observability_logs(true)
            .build(),
    )
    .await;

    // `rule_signer`'s SecretBox zeroizes on drop; the wallet it was derived
    // from has already been disposed inside the shared ceremony helper.
    drop(rule_signer);

    // Best-effort audit writer (sibling convention): an audit-subsystem
    // failure must never mask the outcome of a submission that has already
    // confirmed on-chain.
    let audit_writer = open_audit_writer(&profile_name)
        .map(|(writer, _path)| writer)
        .ok();

    match submit_result {
        Ok(result) => {
            if let Some(writer) = &audit_writer {
                write_success_audit_rows(
                    writer,
                    &account_redacted,
                    args,
                    arg_count,
                    &auth_rule_ids_display,
                    &rule_pubkey_first8,
                    &verifier_c_strkey,
                    &result.tx_hash,
                    chain_id,
                    &request_id,
                );
            }
            info!(
                contract = %redact_strkey_first5_last5(&args.contract),
                function = %args.function,
                arg_count,
                "smart-account execute: submitted",
            );
            let envelope_result = ExecuteResult {
                status: "submitted".to_owned(),
                contract: args.contract.clone(),
                function: args.function.clone(),
                arg_count,
                auth_rule_ids: auth_rule_ids_display,
                rule_signer_pubkey_first8: rule_pubkey_first8,
                verifier_address: verifier_c_strkey,
                tx_hash: Some(result.tx_hash),
            };
            emit_success(&envelope_result, args.output, &request_id)
        }
        Err(e) => {
            if let Some(writer) = &audit_writer {
                write_failure_audit_row(
                    writer,
                    &account_redacted,
                    &e,
                    auth_rule_ids_display.len() as u32,
                    chain_id,
                    &request_id,
                );
            }
            emit_error_sa(&e, args.output, &request_id)
        }
    }
}

/// Writes the `SaRawInvocation` + `SaExternalExecuteSubmitted` audit rows for
/// a successful submission.
#[allow(
    clippy::too_many_arguments,
    reason = "audit-row field set mirrors the domain event"
)]
fn write_success_audit_rows(
    audit_writer: &Arc<Mutex<AuditWriter>>,
    account_redacted: &str,
    args: &ExecuteArgs,
    arg_count: u32,
    auth_rule_ids_display: &[u32],
    rule_pubkey_first8: &str,
    verifier_c_strkey: &str,
    tx_hash: &str,
    chain_id: &str,
    request_id: &str,
) {
    let Ok(mut writer) = audit_writer.lock() else {
        return;
    };
    let raw = AuditEntry::new_sa_raw_invocation(
        account_redacted.to_owned(),
        "sa.ok".to_owned(),
        None,
        auth_rule_ids_display.len() as u32,
        SaInvocationResult::Success,
        chain_id,
        request_id.to_owned(),
    );
    let _ = writer.write_entry(raw);

    let domain = AuditEntry::new_sa_external_execute_submitted(
        RedactedStrkey::from_already_redacted(account_redacted.to_owned()),
        args.contract.clone(),
        args.function.clone(),
        arg_count,
        auth_rule_ids_display.to_vec(),
        rule_pubkey_first8.to_owned(),
        verifier_c_strkey.to_owned(),
        redact_tx_hash(tx_hash),
        chain_id,
        request_id.to_owned(),
    );
    let _ = writer.write_entry(domain);
}

/// Writes the `SaRawInvocation` audit row for a failed submission.
///
/// Uses a minimal phase-based classification tailored to
/// `submit_signed_invoke`'s error surface: `DeploymentFailed` at the
/// `"submit"` / `"deploy"` / `"upload"` / `"post_deploy_verification"`
/// phases is `OnChainRejected`; every other outcome (including the
/// `"simulate"`-phase failures that carry the OZ symbolic error codes) is
/// `PreSubmissionRefused`. Mirrors the phase rule the manager-layer
/// classifier applies to the same `DeploymentFailed` variant.
fn write_failure_audit_row(
    audit_writer: &Arc<Mutex<AuditWriter>>,
    account_redacted: &str,
    err: &SaError,
    auth_rule_ids_count: u32,
    chain_id: &str,
    request_id: &str,
) {
    let Ok(mut writer) = audit_writer.lock() else {
        return;
    };
    let result = classify_invocation_result(err);
    let raw = AuditEntry::new_sa_raw_invocation(
        account_redacted.to_owned(),
        err.wire_code().to_owned(),
        None,
        auth_rule_ids_count,
        result,
        chain_id,
        request_id.to_owned(),
    );
    let _ = writer.write_entry(raw);
}

/// Minimal phase-based `SaError` -> `SaInvocationResult` classifier for the
/// `execute` verb's audit boundary. See [`write_failure_audit_row`].
///
/// A new `SaError` variant that can fail on-chain and is reachable from
/// `execute` must be added to this match explicitly; otherwise it is
/// classified as `PreSubmissionRefused` by the wildcard arm below, which
/// under-counts on-chain failures in the audit log.
fn classify_invocation_result(err: &SaError) -> SaInvocationResult {
    match err {
        SaError::DeploymentFailed {
            phase: "submit" | "deploy" | "upload" | "post_deploy_verification",
            ..
        } => SaInvocationResult::OnChainRejected,
        _ => SaInvocationResult::PreSubmissionRefused,
    }
}

/// Parses a C-strkey via the smart-account crate helper, naming `flag` in
/// the refusal message on failure.
fn parse_c_strkey(flag: &str, s: &str) -> Result<stellar_xdr::ScAddress, WalletError> {
    parse_c_strkey_to_smart_account(s).map_err(|e| {
        WalletError::Validation(ValidationError::AddressInvalid {
            input: format!("{flag}: {e}"),
        })
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Output helpers
// ─────────────────────────────────────────────────────────────────────────────

fn new_request_id() -> String {
    Uuid::new_v4().to_string()
}

fn emit_success(result: &ExecuteResult, output: OutputFormat, request_id: &str) -> i32 {
    let envelope = Envelope::ok_with_request_id(result, request_id.to_owned());
    match output {
        OutputFormat::Table => {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            {
                println!(
                    "execute: submitted  contract={}  function={}  tx_hash={}",
                    result.contract,
                    result.function,
                    result.tx_hash.as_deref().unwrap_or("(none)"),
                );
            }
        }
        _ => render_json(&envelope),
    }
    0
}

fn emit_error(err: &WalletError, output: OutputFormat, request_id: &str) -> i32 {
    let envelope = Envelope::<()>::err_with_request_id(err, request_id.to_owned());
    match output {
        OutputFormat::Table =>
        {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            if let Some(e) = &envelope.error {
                let safe_msg = sanitize_for_table(&e.message);
                println!("Error: {} — {}", e.code, safe_msg);
            }
        }
        _ => render_json(&envelope),
    }
    1
}

fn emit_error_sa(err: &SaError, output: OutputFormat, request_id: &str) -> i32 {
    emit_error(&wrap_sa_error(err), output, request_id)
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
        reason = "test-only assertions"
    )]

    use clap::Parser;
    use serial_test::serial;
    use stellar_agent_core::wallet::{DEFAULT_TTL_SECONDS, MlockRequired, Wallet};
    use stellar_agent_network::signing::wallet::signer_from_wallet;
    use stellar_agent_test_support::StellarAgentHomeGuard;
    use zeroize::Zeroizing;

    use super::*;

    const ACCOUNT_C: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
    const CONTRACT_C: &str = "CBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB4RJU";
    const VOID_ARG_B64: &str = "AAAAAQ==";

    #[derive(Parser, Debug)]
    struct ExecuteArgsHarness {
        #[command(flatten)]
        args: ExecuteArgs,
    }

    fn base_args() -> Vec<&'static str> {
        vec![
            "test",
            "--account",
            ACCOUNT_C,
            "--contract",
            CONTRACT_C,
            "--function",
            "transfer",
            "--auth-rule-id",
            "1",
            "--rule-signer-ed25519-secret-env",
            "__EXEC_TEST_RULE_SIGNER",
            "--signer-secret-env",
            "__EXEC_TEST_FEE_PAYER",
        ]
    }

    // ── Clap matrix ─────────────────────────────────────────────────────────

    #[test]
    fn clap_all_required_flags_parse() {
        let parsed = ExecuteArgsHarness::try_parse_from(base_args());
        assert!(parsed.is_ok(), "base args must parse: {parsed:?}");
    }

    #[test]
    fn clap_missing_account_is_error() {
        let mut a = base_args();
        let idx = a.iter().position(|s| *s == "--account").unwrap();
        a.drain(idx..idx + 2);
        assert!(ExecuteArgsHarness::try_parse_from(a).is_err());
    }

    #[test]
    fn clap_missing_contract_is_error() {
        let mut a = base_args();
        let idx = a.iter().position(|s| *s == "--contract").unwrap();
        a.drain(idx..idx + 2);
        assert!(ExecuteArgsHarness::try_parse_from(a).is_err());
    }

    #[test]
    fn clap_missing_function_is_error() {
        let mut a = base_args();
        let idx = a.iter().position(|s| *s == "--function").unwrap();
        a.drain(idx..idx + 2);
        assert!(ExecuteArgsHarness::try_parse_from(a).is_err());
    }

    /// `--auth-rule-id` has NO default and is required (M4 deviation).
    #[test]
    fn clap_missing_auth_rule_id_is_error() {
        let mut a = base_args();
        let idx = a.iter().position(|s| *s == "--auth-rule-id").unwrap();
        a.drain(idx..idx + 2);
        let result = ExecuteArgsHarness::try_parse_from(a);
        assert!(
            result.is_err(),
            "--auth-rule-id must be required with no default"
        );
    }

    #[test]
    fn clap_missing_rule_signer_secret_env_is_error() {
        let mut a = base_args();
        let idx = a
            .iter()
            .position(|s| *s == "--rule-signer-ed25519-secret-env")
            .unwrap();
        a.drain(idx..idx + 2);
        assert!(ExecuteArgsHarness::try_parse_from(a).is_err());
    }

    /// The fee-payer signer-source group is mutually exclusive.
    #[test]
    fn clap_fee_payer_signer_group_is_mutually_exclusive() {
        let mut a = base_args();
        a.extend(["--sign-with-ledger"]);
        let result = ExecuteArgsHarness::try_parse_from(a);
        assert!(
            result.is_err(),
            "--signer-secret-env + --sign-with-ledger must conflict"
        );
    }

    /// Repeated `--auth-rule-id` flags preserve order.
    #[test]
    fn clap_auth_rule_id_repeatable_order_preserved() {
        let mut a = base_args();
        let idx = a.iter().position(|s| *s == "1").unwrap();
        a[idx] = "3";
        a.extend(["--auth-rule-id", "7", "--auth-rule-id", "2"]);
        let parsed = ExecuteArgsHarness::try_parse_from(a).expect("must parse");
        assert_eq!(parsed.args.auth_rule_id, vec![3, 7, 2]);
    }

    /// Repeated `--arg` flags preserve order.
    #[test]
    fn clap_arg_repeatable_order_preserved() {
        let mut a = base_args();
        a.extend([
            "--arg",
            "AAAAAQ==",
            "--arg",
            VOID_ARG_B64,
            "--arg",
            "AAAAAg==",
        ]);
        let parsed = ExecuteArgsHarness::try_parse_from(a).expect("must parse");
        assert_eq!(
            parsed.args.arg,
            vec![
                "AAAAAQ==".to_owned(),
                VOID_ARG_B64.to_owned(),
                "AAAAAg==".to_owned()
            ]
        );
    }

    #[test]
    fn clap_expect_rule_signer_optional() {
        let parsed = ExecuteArgsHarness::try_parse_from(base_args()).expect("must parse");
        assert!(parsed.args.expect_rule_signer.is_none());

        let mut a = base_args();
        let expected = "aa".repeat(32);
        a.extend(["--expect-rule-signer", &expected]);
        let parsed = ExecuteArgsHarness::try_parse_from(a).expect("must parse");
        assert_eq!(
            parsed.args.expect_rule_signer.as_deref(),
            Some(expected.as_str())
        );
    }

    // ── Envelope shape ──────────────────────────────────────────────────────

    #[test]
    fn execute_result_json_round_trip() {
        let result = ExecuteResult {
            status: "submitted".to_owned(),
            contract: CONTRACT_C.to_owned(),
            function: "transfer".to_owned(),
            arg_count: 3,
            auth_rule_ids: vec![1],
            rule_signer_pubkey_first8: "aabb1122".to_owned(),
            verifier_address: "CVERI...WWWWW".to_owned(),
            tx_hash: Some("a".repeat(64)),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ExecuteResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status, "submitted");
        assert_eq!(back.tx_hash, result.tx_hash);
    }

    // ── M3: synthesized SaError renders through the verb's error path ─────

    #[test]
    fn synthesized_sa_error_renders_oz_annotation_through_wrap_sa_error() {
        let err = SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: "HostError: Error(Contract, #3221) [OZ:SpendingLimitExceeded]"
                .to_owned(),
        };
        match wrap_sa_error(&err) {
            WalletError::SmartAccount { wire_code, message } => {
                assert_eq!(wire_code, "sa.deployment_failed");
                assert!(
                    message.contains("[OZ:SpendingLimitExceeded]"),
                    "OZ annotation must survive the verb's error mapping: {message}"
                );
            }
            other => panic!("expected WalletError::SmartAccount, got {other:?}"),
        }
    }

    #[test]
    fn classify_invocation_result_maps_submit_phase_on_chain_rejected() {
        let err = SaError::DeploymentFailed {
            phase: "submit",
            redacted_reason: "boom".to_owned(),
        };
        assert_eq!(
            classify_invocation_result(&err),
            SaInvocationResult::OnChainRejected
        );
    }

    #[test]
    fn classify_invocation_result_maps_simulate_phase_pre_submission_refused() {
        let err = SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: "boom".to_owned(),
        };
        assert_eq!(
            classify_invocation_result(&err),
            SaInvocationResult::PreSubmissionRefused
        );
    }

    // ── Runtime refusals ────────────────────────────────────────────────────

    fn minimal_args() -> ExecuteArgs {
        ExecuteArgs {
            account: ACCOUNT_C.to_owned(),
            contract: CONTRACT_C.to_owned(),
            function: "transfer".to_owned(),
            arg: vec![],
            auth_rule_id: vec![1],
            rule_signer_ed25519_secret_env: "__EXEC_TEST_RULE_SIGNER_RUNTIME".to_owned(),
            expect_rule_signer: None,
            verifier: None,
            signer_source: SignerSourceFlags {
                signer_secret_env: Some("__EXEC_TEST_FEE_PAYER_RUNTIME".to_owned()),
                sign_with_ledger: false,
                account_index: Some(0),
            },
            profile: None,
            network: TargetNetwork::Testnet,
            rpc_url: TESTNET_RPC_URL.to_owned(),
            secondary_rpc_url: None,
            timeout_seconds: 1,
            output: OutputFormat::Json,
        }
    }

    /// Mainnet is refused before any RPC call — non-routable RPC URL ensures
    /// an accidental call would fail with a connection error, not silently
    /// succeed.
    #[tokio::test]
    async fn mainnet_refused_before_any_network_call() {
        let mut args = minimal_args();
        args.network = TargetNetwork::Mainnet;
        args.rpc_url = "http://127.0.0.1:1".to_owned();
        let code = run(&args).await;
        assert_eq!(code, 1, "mainnet must exit with code 1");
    }

    /// An empty `--function` is refused client-side.
    #[tokio::test]
    async fn empty_function_refused_client_side() {
        let mut args = minimal_args();
        args.function = String::new();
        args.rpc_url = "http://127.0.0.1:1".to_owned();
        let code = run(&args).await;
        assert_eq!(code, 1, "empty function name must be refused");
    }

    /// A malformed `--arg` is refused client-side with the failing index named.
    #[tokio::test]
    async fn malformed_arg_refused_with_index() {
        let mut args = minimal_args();
        args.arg = vec![VOID_ARG_B64.to_owned(), "not-valid-base64!!".to_owned()];
        args.rpc_url = "http://127.0.0.1:1".to_owned();
        let code = run(&args).await;
        assert_eq!(code, 1, "malformed --arg must be refused");
    }

    // ── Typed refusal pins (validate_execute_inputs) ────────────────────────
    // The run()-level tests above prove the exit code end to end; these pin
    // the SPECIFIC typed refusal so deleting a guard cannot pass unnoticed
    // behind an unrelated exit-1 path.

    /// Mainnet is the FIRST structural refusal, with its exact wire code.
    #[test]
    fn validate_inputs_mainnet_yields_mainnet_write_forbidden() {
        let mut args = minimal_args();
        args.network = TargetNetwork::Mainnet;
        let err = validate_execute_inputs(&args).expect_err("mainnet must refuse");
        assert_eq!(err.code(), "network.mainnet_write_forbidden");
    }

    /// An empty `--function` yields the validation wire code and names the
    /// flag in the message.
    #[test]
    fn validate_inputs_empty_function_names_the_flag() {
        let mut args = minimal_args();
        args.function = String::new();
        let err = validate_execute_inputs(&args).expect_err("empty function must refuse");
        assert_eq!(err.code(), "validation.address_invalid");
        assert!(
            err.to_string().contains("--function"),
            "message must name --function; got: {err}"
        );
    }

    /// A malformed `--arg` yields `XdrArgumentMalformed` naming the failing
    /// index — index 1 here, proving the error points at the bad value, not
    /// merely at "some argument".
    #[test]
    fn validate_inputs_malformed_arg_names_failing_index() {
        let mut args = minimal_args();
        args.arg = vec![VOID_ARG_B64.to_owned(), "not-valid-base64!!".to_owned()];
        let err = validate_execute_inputs(&args).expect_err("malformed arg must refuse");
        assert_eq!(err.code(), "validation.xdr_argument_malformed");
        assert!(
            err.to_string().contains("--arg[1]"),
            "message must name the failing index --arg[1]; got: {err}"
        );
    }

    /// With no `--verifier` and no registry entry, resolution fails closed
    /// naming the deploy verb.
    #[test]
    fn validate_inputs_missing_verifier_fails_closed_naming_deploy_verb() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let _home = StellarAgentHomeGuard::new(dir.path());
        let mut args = minimal_args();
        args.verifier = None;
        let err = validate_execute_inputs(&args).expect_err("missing verifier must refuse");
        assert_eq!(err.code(), "validation.address_invalid");
        assert!(
            err.to_string().contains("deploy-ed25519-verifier"),
            "message must name the deploy verb; got: {err}"
        );
    }

    /// The happy path produces a plan whose fields mirror the inputs.
    #[test]
    fn validate_inputs_happy_path_builds_the_plan() {
        // Checksum-valid C-strkey (the testnet XLM SAC); the module's
        // synthetic ACCOUNT_C/CONTRACT_C constants are shape-only fixtures
        // for clap tests and do not pass strkey checksum validation.
        const VALID_C: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
        let mut args = minimal_args();
        args.account = VALID_C.to_owned();
        args.contract = VALID_C.to_owned();
        args.verifier = Some(VALID_C.to_owned());
        args.arg = vec![VOID_ARG_B64.to_owned()];
        let plan = validate_execute_inputs(&args).expect("valid inputs must produce a plan");
        assert_eq!(plan.arg_count, 1);
        assert_eq!(plan.verifier_c_strkey, VALID_C);
        assert!(matches!(
            plan.host_function,
            HostFunction::InvokeContract(_)
        ));
    }

    /// No Ed25519 verifier registered + no `--verifier` override is refused
    /// before any RPC call.
    #[tokio::test]
    #[serial]
    async fn missing_verifier_refused_before_any_network_call() {
        let dir = tempfile::TempDir::new().unwrap();
        let _guard = StellarAgentHomeGuard::new(dir.path());

        let mut args = minimal_args();
        args.rpc_url = "http://127.0.0.1:1".to_owned();
        let code = run(&args).await;
        assert_eq!(
            code, 1,
            "missing verifier registration must be refused before any network call"
        );
    }

    // ── Seed-ceremony ───────────────────────────────────────────────────────

    /// S-strkey env -> derived pubkey matches the ed25519-dalek verifying key.
    #[tokio::test]
    async fn seed_ceremony_derives_matching_pubkey() {
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        let seed_bytes = signing_key.to_bytes();
        let s_strkey = stellar_strkey::ed25519::PrivateKey::from_payload(&seed_bytes)
            .unwrap()
            .as_unredacted()
            .to_string()
            .as_str()
            .to_owned();

        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(seed_bytes);
        let wallet = Wallet::unlock(
            "seed-ceremony-test".to_owned(),
            seed,
            DEFAULT_TTL_SECONDS,
            MlockRequired::Warn,
        )
        .await
        .unwrap();
        let signer = signer_from_wallet(&wallet).unwrap();
        let derived_pubkey = signer.public_key().await.unwrap();
        drop(signer);
        let mut wallet = wallet;
        wallet.dispose();

        let expected_pubkey = signing_key.verifying_key().to_bytes();
        assert_eq!(
            derived_pubkey.0, expected_pubkey,
            "the seed-derived pubkey must match the ed25519-dalek verifying key"
        );

        // Sanity: the S-strkey we constructed round-trips to the same seed.
        let reparsed = stellar_strkey::ed25519::PrivateKey::from_string(&s_strkey).unwrap();
        assert_eq!(reparsed.0, seed_bytes);
    }
}
