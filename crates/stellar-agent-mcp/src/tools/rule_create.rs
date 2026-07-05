//! `stellar_rule_create` and `stellar_rule_create_commit` MCP tools
//! (Package D, GH issue #8).
//!
//! Simulate-then-commit pair letting an MCP agent PROPOSE an OZ
//! `add_context_rule` installation — including rules whose signer sets
//! contain human passkeys — without ever holding rule-write authority.
//!
//! `stellar_rule_create` resolves the full rule definition (context, name,
//! expiry, signers, policies, auth_rule_ids), runs the SAME wasm-hash pin
//! check `install_rule` runs, simulates via
//! [`stellar_agent_smart_account::managers::rules::ContextRuleManager::simulate_install_rule`],
//! mints the domain-separated `proposal_sha256` digest, and parks the FULLY
//! RESOLVED snapshot as an `ApprovalKind::RuleProposalSimulated` pending
//! approval. `stellar_rule_create_commit` verifies the operator's HMAC
//! attestation over that digest (via the DEDICATED
//! `PendingApprovalStore::verify_rule_proposal_gate` — the shared pay/claim
//! `verify_attestation_gate` is NOT used here and its `other =>` fallback
//! continues to reject this kind), re-derives the digest from the SAME
//! stored snapshot to confirm no drift, and calls the unchanged
//! `ContextRuleManager::install_rule`.
//!
//! # Why no envelope_xdr / nonce_mint
//!
//! Unlike `stellar_pay` / `stellar_claim`, there is no unsigned envelope
//! handed from simulate to commit: `install_rule` re-derives and resubmits
//! the `add_context_rule` invocation itself at commit time. The pending
//! approval's `approval_nonce` is therefore the SOLE identifier binding a
//! commit call to a specific proposal — `approval_nonce` is a REQUIRED
//! (never optional) field on [`StellarRuleCreateCommitArgs`], unlike
//! pay/claim's optional `approval_nonce` (which is only present on the
//! `RequireApproval` policy path).
//!
//! # Credential resolution at propose time
//!
//! A `signers: [{ kind: "webauthn", credential_name }]` entry is resolved
//! into raw bytes (`pubkey_65 || credential_id`, the OZ canonical WebAuthn
//! verifier layout) AT PROPOSE TIME via the profile's passkey store and the
//! `VerifierRegistry` — never at commit. This freezes exactly what the
//! operator will see and closes the uncompletable-flow class (a credential
//! NAME reference resolved at commit time could point at a renamed/deleted
//! credential by then).
//!
//! # Mainnet write defence
//!
//! Both tools structurally refuse a `stellar:mainnet` `chain_id`
//! (`network.mainnet_write_forbidden`), matching every other smart-account
//! write surface (`stellar-agent smart-account rules create`, `add-policy`,
//! etc.). `stellar_rule_create` refuses at propose time, before any RPC
//! call; `stellar_rule_create_commit` refuses AGAIN at commit time as
//! defense in depth — it does not rely solely on the propose-time refusal,
//! since a commit call's `chain_id` is caller-supplied and independent of
//! whatever chain_id a (possibly different) propose call used.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_mcp_macros::mcp_tool_router;

use stellar_agent_core::approval::rule_proposal::{
    ContextRuleProposalSnapshot, RuleProposalContextType, RuleProposalPolicy, RuleProposalSigner,
};
use stellar_agent_core::approval::store::PendingApproval;
use stellar_agent_core::approval::user_id::process_uid_for_attestation;
use stellar_agent_core::approval::{
    DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, RuleProposalGateError, open_with_retry,
};
use stellar_agent_core::audit_log::writer::{AuditWriter, AuditWriterRegistry};
use stellar_agent_core::profile::schema::default_audit_log_path_for;
use stellar_agent_core::timefmt::now_unix_ms;
use stellar_agent_network::keyring::signer_from_keyring;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::credentials::CredentialsManager;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRuleManager, ContextRuleManagerConfig, ContextRulePolicy,
    ContextRuleSignerInput, OZ_MAX_EXTERNAL_KEY_SIZE, OZ_MAX_NAME_SIZE, OZ_MAX_POLICIES,
    OZ_MAX_SIGNERS, RuleContext, compute_context_rule_proposal_sha256,
    context_rule_definition_from_snapshot, parse_c_strkey_to_smart_account,
    parse_g_strkey_to_signer_address,
};
use stellar_agent_smart_account::managers::signers::{SignersManager, SignersManagerConfig};
use stellar_agent_smart_account::spending_limit_policy::{
    build_spending_limit_install_param, ensure_call_contract_context_for_spending_limit,
    ensure_valid_spending_limit_params,
};
use stellar_agent_smart_account::verifiers::VerifierRegistry;
use stellar_xdr::{Limits, ReadXdr as _, ScVal, WriteXdr as _};

use crate::server::WalletServer;
use crate::tools::common::{DispatchOutcome, approval_rejected_error, load_attestation_key};

/// Default submission-equivalent timeout (simulate + submit) in seconds.
const DEFAULT_TIMEOUT_SECONDS: u64 = 60;

/// Default `auth_rule_ids` when the caller omits the field: the
/// constructor-installed bootstrap rule (rule ID `0`) from `accounts
/// deploy-c`. Mirrors the CLI `smart-account rules create` default.
fn default_auth_rule_ids() -> Vec<u32> {
    vec![0]
}

// ─────────────────────────────────────────────────────────────────────────────
// Argument grammar
// ─────────────────────────────────────────────────────────────────────────────

/// One signer entry in `stellar_rule_create`'s `signers` array.
///
/// - `delegated`: a G-strkey (ed25519-keyed delegate) or C-strkey
///   (contract-mediated signer).
/// - `external`: raw escape hatch — an explicit verifier C-strkey and
///   hex-encoded `pubkey_data`, passed through unresolved (mirrors the
///   `raw` policy-kind precedent: a typed convenience path plus a raw
///   passthrough for signer shapes the typed resolvers don't cover).
/// - `webauthn`: a passkey credential name, resolved into
///   `pubkey_65 || credential_id` bytes at propose time via the profile's
///   passkey store and the `VerifierRegistry`.
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde", tag = "kind", rename_all = "snake_case")]
pub enum RuleCreateSignerArg {
    /// Delegated (built-in ed25519, or contract-mediated) signer.
    Delegated {
        /// G-strkey or C-strkey.
        address: String,
    },
    /// Raw `External` signer: explicit verifier + hex pubkey_data.
    External {
        /// Verifier-contract C-strkey.
        verifier: String,
        /// Hex-encoded verifier-specific public-key bytes.
        pubkey_data_hex: String,
    },
    /// WebAuthn passkey co-signer, resolved by credential name.
    Webauthn {
        /// Name as stored via `credentials add-passkey`.
        credential_name: String,
    },
}

/// One policy entry in `stellar_rule_create`'s `policies` array.
///
/// - `raw`: operator-facing escape hatch — an explicit policy C-strkey and
///   base64 (URL-safe, no padding) XDR `ScVal` install parameter, passed
///   through unvalidated.
/// - `spending_limit`: typed spending-limit policy. Resolves the deployed
///   OZ spending-limit policy from the `VerifierRegistry` (or the
///   `policy_address` override), builds the `SpendingLimitAccountParams`
///   install param from `limit_stroops` + `period_ledgers`, and refuses
///   non-`CallContract` rules (OZ `install` rejects them with
///   `OnlyCallContractAllowed`).
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde", tag = "kind", rename_all = "snake_case")]
pub enum RuleCreatePolicyArg {
    /// Raw passthrough.
    Raw {
        /// Policy-contract C-strkey.
        policy_address: String,
        /// Base64 (URL-safe, no padding) XDR `ScVal` install parameter.
        install_param_xdr_b64: String,
    },
    /// Typed spending-limit policy.
    SpendingLimit {
        /// Spending limit in stroops, as a decimal string.
        ///
        /// Wire type is `String`, not `i128`: the toolset dispatcher routes
        /// tool args through `serde_json::from_value` on an already-parsed
        /// `serde_json::Value`, which does not support `i128`/`u128`
        /// deserialisation (a `serde_json` limitation distinct from parsing
        /// i128 directly from a JSON token stream). Decimal-string is the
        /// established wire convention for i128 quantities in this codebase.
        limit_stroops: String,
        /// Rolling-window length in ledgers.
        period_ledgers: u32,
        /// Optional policy-contract C-strkey override; defaults to the
        /// network's registered spending-limit policy.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy_address: Option<String>,
    },
}

/// Arguments for the `stellar_rule_create` (propose) MCP tool.
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct StellarRuleCreateArgs {
    /// CAIP-2 chain identifier: `stellar:testnet` or `stellar:mainnet`.
    pub chain_id: String,

    /// Smart-account contract C-strkey to install the rule on.
    pub smart_account: String,

    /// Context the rule authorizes. Accepted forms:
    /// `"default"`, `"call-contract:<C-strkey>"`,
    /// `"create-contract:<64-hex-wasm-hash>"`. Defaults to `"default"`.
    #[serde(default = "default_context_arg")]
    pub context: String,

    /// Operator-facing rule name. OZ length cap (20 bytes) enforced.
    pub name: String,

    /// Optional ledger sequence at which the rule expires. `None` (or
    /// omitted) means permanent.
    #[serde(default)]
    pub valid_until: Option<u32>,

    /// Signer set. At least one entry required. OZ `MAX_SIGNERS = 15` cap
    /// enforced client-side before any RPC round-trip.
    pub signers: Vec<RuleCreateSignerArg>,

    /// Policy set. OZ `MAX_POLICIES = 5` cap enforced client-side.
    #[serde(default)]
    pub policies: Vec<RuleCreatePolicyArg>,

    /// Auth rule-id(s) whose signers authorize this install. Defaults to
    /// `[0]` (the bootstrap rule).
    #[serde(default = "default_auth_rule_ids")]
    pub auth_rule_ids: Vec<u32>,

    /// Opt-in to proposing a rule whose verifier or policy contract has a
    /// mutable admin/owner key. See `smart-account rules create
    /// --accept-mutable-verifier` for the on-chain rationale.
    #[serde(default)]
    pub accept_mutable_verifier: bool,

    /// Opt-in to proposing a rule whose verifier or policy wasm hash is not
    /// in the compile-time allowlist.
    #[serde(default)]
    pub accept_unknown_verifier: bool,

    /// Acknowledge that this rule has no delegated (ed25519) fallback
    /// signer — required when every signer is `webauthn` and no
    /// `delegated` entry is present. Mirrors the CLI's
    /// `--accept-no-delegated-fallback` passkey-only refusal.
    #[serde(default)]
    pub accept_no_delegated_fallback: bool,
}

fn default_context_arg() -> String {
    "default".to_owned()
}

/// Arguments for the `stellar_rule_create_commit` (commit) MCP tool.
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct StellarRuleCreateCommitArgs {
    /// CAIP-2 chain identifier: `stellar:testnet` or `stellar:mainnet`.
    pub chain_id: String,

    /// Wallet-issued approval nonce from the `stellar_rule_create` response.
    ///
    /// REQUIRED (unlike pay/claim's optional `approval_nonce`): the
    /// resolved rule definition lives ONLY in the pending-approval store —
    /// there is no `envelope_xdr` fallback carrying it.
    pub approval_nonce: String,

    /// HMAC-SHA256 attestation blob, URL-safe base64 no-pad encoded (32
    /// bytes). Required when the policy engine (or the toolset-gated forced
    /// path) requires approval.
    #[serde(default)]
    pub approval_attestation: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// --context grammar (mirrors the CLI's `parse_rule_context`)
// ─────────────────────────────────────────────────────────────────────────────

const CONTEXT_GRAMMAR: &str = "accepted context forms: 'default' (or omit the field), \
     'call-contract:<C-strkey>', 'create-contract:<64-hex-wasm-hash>'";

fn parse_rule_context_arg(s: &str) -> Result<RuleContext, String> {
    if s.eq_ignore_ascii_case("default") {
        return Ok(RuleContext::Default);
    }
    if let Some(strkey) = s.strip_prefix("call-contract:") {
        let contract = parse_c_strkey_to_smart_account(strkey).map_err(|_| {
            format!("call-contract target is not a valid C-strkey; {CONTEXT_GRAMMAR}")
        })?;
        return Ok(RuleContext::CallContract { contract });
    }
    if let Some(hex_hash) = s.strip_prefix("create-contract:") {
        if hex_hash.len() != 64 {
            return Err(format!(
                "create-contract wasm hash must be 64 hex chars (32 bytes), got {}; \
                 {CONTEXT_GRAMMAR}",
                hex_hash.len()
            ));
        }
        let bytes = hex::decode(hex_hash).map_err(|_| {
            format!("create-contract wasm hash is not valid hex; {CONTEXT_GRAMMAR}")
        })?;
        let wasm_hash: [u8; 32] = bytes.try_into().map_err(|_| {
            format!("create-contract wasm hash did not decode to 32 bytes; {CONTEXT_GRAMMAR}")
        })?;
        return Ok(RuleContext::CreateContract { wasm_hash });
    }
    Err(format!("unknown context '{s}'; {CONTEXT_GRAMMAR}"))
}

/// Renders a [`RuleContext`] back into its core-side
/// [`RuleProposalContextType`] (the snapshot representation).
fn context_type_to_snapshot(context: &RuleContext) -> Result<RuleProposalContextType, String> {
    match context {
        RuleContext::Default => Ok(RuleProposalContextType::Default),
        RuleContext::CallContract { contract } => {
            // `RuleContext::CallContract` always wraps `ScAddress::Contract`
            // (by construction: `parse_c_strkey_to_smart_account` /
            // `parse_rule_context_arg`'s `call-contract:<C-strkey>` arm are
            // the only producers). A non-Contract address is structurally
            // unreachable but handled defensively rather than panicking.
            let stellar_xdr::ScAddress::Contract(stellar_xdr::ContractId(stellar_xdr::Hash(bytes))) =
                contract
            else {
                return Err(
                    "call-contract target is not a Contract address (structurally unreachable)"
                        .to_owned(),
                );
            };
            let strkey = stellar_strkey::Contract(*bytes)
                .to_string()
                .as_str()
                .to_owned();
            Ok(RuleProposalContextType::CallContract { contract: strkey })
        }
        RuleContext::CreateContract { wasm_hash } => Ok(RuleProposalContextType::CreateContract {
            wasm_hash_hex: wasm_hash.iter().map(|b| format!("{b:02x}")).collect(),
        }),
        // `RuleContext` is `#[non_exhaustive]` (defined in
        // stellar-agent-smart-account); a future variant fails closed here
        // rather than silently falling through.
        other => Err(format!(
            "context: unrecognised RuleContext variant {other:?}"
        )),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Signer resolution
// ─────────────────────────────────────────────────────────────────────────────

/// Resolved signer set: both the typed smart-account representation (used
/// for simulate + digest) and the core snapshot representation (used for
/// storage), built together from the SAME source bytes so the two can never
/// drift.
#[derive(Debug)]
struct ResolvedSigners {
    typed: Vec<ContextRuleSignerInput>,
    snapshot: Vec<RuleProposalSigner>,
    /// `true` if at least one `delegated` entry is present (passkey-only
    /// fallback check).
    has_delegated: bool,
}

/// Resolves `signers` into both representations, tagging `is_proposer` on
/// any `Delegated` entry whose address equals the agent's own MCP signing
/// identity (`profile.mcp_signer_default.account`).
///
/// Only `Delegated` signers can ever be the proposing agent's own key: the
/// agent signs via its keyring-held ed25519 secret, never via a WebAuthn
/// ceremony or an arbitrary raw external key.
#[allow(
    clippy::result_large_err,
    reason = "SaError::SignerSetDiverged carries full diagnostic state by design \
              (see stellar-agent-smart-account's crate-level allow); an intermediate \
              closure result briefly holds it before mapping to rmcp::ErrorData"
)]
fn resolve_signers(
    signers: &[RuleCreateSignerArg],
    server: &WalletServer,
) -> Result<ResolvedSigners, rmcp::ErrorData> {
    if signers.is_empty() {
        return Err(rmcp::ErrorData::invalid_params(
            "signers must be non-empty (at least one signer required)",
            None,
        ));
    }
    if signers.len() > OZ_MAX_SIGNERS as usize {
        return Err(rmcp::ErrorData::invalid_params(
            format!(
                "signers must have at most {OZ_MAX_SIGNERS} entries (OZ MAX_SIGNERS), got {}",
                signers.len()
            ),
            None,
        ));
    }

    let agent_g = server.profile.mcp_signer_default.account.clone();
    let mut typed = Vec::with_capacity(signers.len());
    let mut snapshot = Vec::with_capacity(signers.len());
    let mut has_delegated = false;

    for (idx, s) in signers.iter().enumerate() {
        match s {
            RuleCreateSignerArg::Delegated { address } => {
                has_delegated = true;
                let is_proposer = address == &agent_g;
                let sc_addr = parse_g_strkey_to_signer_address(address)
                    .or_else(|_| parse_c_strkey_to_smart_account(address))
                    .map_err(|e| {
                        rmcp::ErrorData::invalid_params(
                            format!("signers[{idx}].address: invalid G/C-strkey: {e}"),
                            None,
                        )
                    })?;
                typed.push(ContextRuleSignerInput::Delegated { address: sc_addr });
                snapshot.push(RuleProposalSigner::delegated(address.clone(), is_proposer));
            }
            RuleCreateSignerArg::External {
                verifier,
                pubkey_data_hex,
            } => {
                let verifier_addr = parse_c_strkey_to_smart_account(verifier).map_err(|e| {
                    rmcp::ErrorData::invalid_params(
                        format!("signers[{idx}].verifier: invalid C-strkey: {e}"),
                        None,
                    )
                })?;
                let pubkey_data = hex::decode(pubkey_data_hex).map_err(|e| {
                    rmcp::ErrorData::invalid_params(
                        format!("signers[{idx}].pubkey_data_hex: invalid hex: {e}"),
                        None,
                    )
                })?;
                if pubkey_data.len() > OZ_MAX_EXTERNAL_KEY_SIZE {
                    return Err(rmcp::ErrorData::invalid_params(
                        format!(
                            "signers[{idx}].pubkey_data_hex: decodes to {} bytes, max is \
                             {OZ_MAX_EXTERNAL_KEY_SIZE} (OZ MAX_EXTERNAL_KEY_SIZE)",
                            pubkey_data.len()
                        ),
                        None,
                    ));
                }
                typed.push(ContextRuleSignerInput::External {
                    verifier: verifier_addr,
                    pubkey_data: pubkey_data.clone(),
                });
                snapshot.push(RuleProposalSigner::external(
                    verifier.clone(),
                    pubkey_data,
                    false,
                ));
            }
            RuleCreateSignerArg::Webauthn { credential_name } => {
                let (verifier_strkey, verifier_addr, pubkey_data) =
                    resolve_webauthn_signer(credential_name, server, idx)?;
                typed.push(ContextRuleSignerInput::External {
                    verifier: verifier_addr,
                    pubkey_data: pubkey_data.clone(),
                });
                snapshot.push(RuleProposalSigner::external(
                    verifier_strkey,
                    pubkey_data,
                    false,
                ));
            }
        }
    }

    Ok(ResolvedSigners {
        typed,
        snapshot,
        has_delegated,
    })
}

/// Resolves a `webauthn` signer entry: looks up `credential_name` in the
/// profile's passkey store, decodes `public_key_sec1_b64` (65-byte
/// uncompressed SEC1 P-256) and `credential_id_b64url`, and concatenates
/// `pubkey_data = pubkey_65_bytes || credential_id_bytes` per the OZ
/// `canonicalize_key` WebAuthn verifier convention
/// (`verifiers/webauthn.rs:373-377`). The verifier-contract address is read
/// from the `VerifierRegistry` for the profile's network.
///
/// Returns `(verifier_c_strkey, verifier_sc_address, pubkey_data)`.
fn resolve_webauthn_signer(
    credential_name: &str,
    server: &WalletServer,
    idx: usize,
) -> Result<(String, stellar_xdr::ScAddress, Vec<u8>), rmcp::ErrorData> {
    let bad = |detail: String| {
        rmcp::ErrorData::invalid_params(
            format!("signers[{idx}].credential_name '{credential_name}': {detail}"),
            None,
        )
    };

    let registry = VerifierRegistry::open()
        .map_err(|e| bad(format!("could not open verifier registry: {e}")))?;
    let verifier_entry = registry
        .webauthn_verifier_for(&server.profile.network_passphrase)
        .ok_or_else(|| {
            bad("no WebAuthn verifier deployed for this network; run \
                 `smart-account deploy-webauthn-verifier`"
                .to_owned())
        })?;
    let verifier_strkey = verifier_entry.address.clone();
    let verifier_addr = parse_c_strkey_to_smart_account(&verifier_strkey)
        .map_err(|e| bad(format!("verifier registry address invalid: {e}")))?;

    let profile_name = server.profile_name_for_approval();
    let creds_mgr = CredentialsManager::from_defaults_readonly(&profile_name, "localhost")
        .map_err(|e| bad(format!("could not open passkeys registry: {e}")))?;
    let metadata = creds_mgr
        .show(credential_name)
        .map_err(|e| bad(format!("{e}")))?;

    if metadata.public_key_sec1_b64.is_empty() {
        return Err(bad(
            "credential is missing public_key_sec1_b64 (delete and re-register)".to_owned(),
        ));
    }
    let pubkey_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&metadata.public_key_sec1_b64)
        .map_err(|_| bad("public_key_sec1_b64 is not valid base64url".to_owned()))?;
    if pubkey_bytes.len() != 65 {
        return Err(bad(format!(
            "public_key_sec1_b64 decodes to {} bytes, expected 65",
            pubkey_bytes.len()
        )));
    }
    let credential_id_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&metadata.credential_id_b64url)
        .map_err(|_| bad("credential_id_b64url is not valid base64url".to_owned()))?;

    // pubkey_data = pubkey_65_bytes || credential_id_bytes. Canonical
    // concatenation; MUST NOT be reordered (OZ `canonicalize_key`
    // convention, verifiers/webauthn.rs:373-377).
    let mut pubkey_data = Vec::with_capacity(65 + credential_id_bytes.len());
    pubkey_data.extend_from_slice(&pubkey_bytes);
    pubkey_data.extend_from_slice(&credential_id_bytes);

    if pubkey_data.len() > OZ_MAX_EXTERNAL_KEY_SIZE {
        return Err(bad(format!(
            "resolved pubkey_data is {} bytes, max is {OZ_MAX_EXTERNAL_KEY_SIZE} \
             (OZ MAX_EXTERNAL_KEY_SIZE)",
            pubkey_data.len()
        )));
    }

    Ok((verifier_strkey, verifier_addr, pubkey_data))
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy resolution
// ─────────────────────────────────────────────────────────────────────────────

fn resolve_policies(
    policies: &[RuleCreatePolicyArg],
    context: &RuleContext,
    network_passphrase: &str,
) -> Result<(Vec<ContextRulePolicy>, Vec<RuleProposalPolicy>), rmcp::ErrorData> {
    if policies.len() > OZ_MAX_POLICIES as usize {
        return Err(rmcp::ErrorData::invalid_params(
            format!(
                "policies must have at most {OZ_MAX_POLICIES} entries (OZ MAX_POLICIES), got {}",
                policies.len()
            ),
            None,
        ));
    }

    let mut typed = Vec::with_capacity(policies.len());
    let mut snapshot = Vec::with_capacity(policies.len());

    for (idx, p) in policies.iter().enumerate() {
        let (policy_addr, policy_strkey, params) = match p {
            RuleCreatePolicyArg::Raw {
                policy_address,
                install_param_xdr_b64,
            } => {
                let addr = parse_c_strkey_to_smart_account(policy_address).map_err(|e| {
                    rmcp::ErrorData::invalid_params(
                        format!("policies[{idx}].policy_address: invalid C-strkey: {e}"),
                        None,
                    )
                })?;
                // Bounded decode (depth=500, len=10 MiB) — same convention as
                // the CLI `rules add-policy --kind raw --install-param` path.
                let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(install_param_xdr_b64)
                    .map_err(|e| {
                        rmcp::ErrorData::invalid_params(
                            format!(
                                "policies[{idx}].install_param_xdr_b64: not valid base64url: {e}"
                            ),
                            None,
                        )
                    })?;
                let scval = ScVal::from_xdr(
                    decoded,
                    Limits {
                        depth: 500,
                        len: 10 * 1024 * 1024,
                    },
                )
                .map_err(|e| {
                    rmcp::ErrorData::invalid_params(
                        format!("policies[{idx}].install_param_xdr_b64: XDR decode failed: {e:?}"),
                        None,
                    )
                })?;
                (addr, policy_address.clone(), scval)
            }
            RuleCreatePolicyArg::SpendingLimit {
                limit_stroops,
                period_ledgers,
                policy_address,
            } => {
                let limit_stroops: i128 = limit_stroops.parse().map_err(|_| {
                    rmcp::ErrorData::invalid_params(
                        format!(
                            "policies[{idx}].limit_stroops: not a valid decimal i128: \
                             {limit_stroops:?}"
                        ),
                        None,
                    )
                })?;
                ensure_valid_spending_limit_params(limit_stroops, *period_ledgers).map_err(
                    |e| rmcp::ErrorData::invalid_params(format!("policies[{idx}]: {e}"), None),
                )?;
                ensure_call_contract_context_for_spending_limit(context).map_err(|e| {
                    rmcp::ErrorData::invalid_params(format!("policies[{idx}]: {e}"), None)
                })?;
                let strkey = if let Some(explicit) = policy_address {
                    explicit.clone()
                } else {
                    let registry = VerifierRegistry::open().map_err(|e| {
                        rmcp::ErrorData::invalid_params(
                            format!("policies[{idx}]: could not open verifier registry: {e}"),
                            None,
                        )
                    })?;
                    let entry = registry
                        .spending_limit_policy_for(network_passphrase)
                        .ok_or_else(|| {
                            rmcp::ErrorData::invalid_params(
                                format!(
                                    "policies[{idx}]: no spending-limit policy deployed for \
                                     this network; run \
                                     `smart-account deploy-spending-limit-policy` or pass \
                                     policy_address"
                                ),
                                None,
                            )
                        })?;
                    entry.address.clone()
                };
                let addr = parse_c_strkey_to_smart_account(&strkey).map_err(|e| {
                    rmcp::ErrorData::invalid_params(
                        format!("policies[{idx}].policy_address: invalid C-strkey: {e}"),
                        None,
                    )
                })?;
                let scval = build_spending_limit_install_param(limit_stroops, *period_ledgers)
                    .map_err(|e| {
                        rmcp::ErrorData::invalid_params(format!("policies[{idx}]: {e}"), None)
                    })?;
                (addr, strkey, scval)
            }
        };

        let params_xdr = params.to_xdr(Limits::none()).map_err(|e| {
            rmcp::ErrorData::internal_error(
                format!("policies[{idx}]: install-param XDR encode failed: {e:?}"),
                None,
            )
        })?;
        let params_xdr_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(params_xdr);

        typed.push(ContextRulePolicy::new(policy_addr, params));
        snapshot.push(RuleProposalPolicy::new(policy_strkey, params_xdr_b64));
    }

    Ok((typed, snapshot))
}

// ─────────────────────────────────────────────────────────────────────────────
// Manager construction — REAL per-operator profile (not the fixed
// observability profile the read-only rules.rs tools use)
// ─────────────────────────────────────────────────────────────────────────────

#[allow(
    clippy::result_large_err,
    reason = "SaError::SignerSetDiverged carries full diagnostic state by design \
              (see stellar-agent-smart-account's crate-level allow); this fn simply \
              propagates it"
)]
fn open_rule_create_audit_writer(
    server: &WalletServer,
) -> Result<Arc<Mutex<AuditWriter>>, SaError> {
    let profile_name = server.profile_name_for_approval();
    let log_path = default_audit_log_path_for(&profile_name);
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SaError::NetworksTomlIo {
            source: e,
            path: log_path.clone(),
        })?;
    }
    AuditWriterRegistry::get_or_open(&profile_name, &log_path, None).map_err(|e| {
        SaError::NetworksTomlIo {
            source: std::io::Error::other(e.to_string()),
            path: log_path,
        }
    })
}

#[allow(
    clippy::result_large_err,
    reason = "SaError::SignerSetDiverged carries full diagnostic state by design \
              (see stellar-agent-smart-account's crate-level allow); this fn simply \
              propagates it"
)]
fn build_write_context_rule_manager(server: &WalletServer) -> Result<ContextRuleManager, SaError> {
    let audit_writer = open_rule_create_audit_writer(server)?;
    let rpc_url = server.profile.rpc_url.as_str();
    let network_passphrase = server.profile.network_passphrase.as_str();
    let chain_id = server.profile.chain_id.caip2_str();

    let log_path = default_audit_log_path_for(&server.profile_name_for_approval());
    let signers_manager = SignersManager::new(SignersManagerConfig::new(
        rpc_url.to_owned(),
        rpc_url.to_owned(),
        Arc::clone(&audit_writer),
        log_path,
        network_passphrase.to_owned(),
        server.profile_name_for_approval(),
        Duration::from_secs(DEFAULT_TIMEOUT_SECONDS),
        chain_id.to_owned(),
    ))?;

    let config = ContextRuleManagerConfig::new(
        rpc_url.to_owned(),
        network_passphrase.to_owned(),
        Duration::from_secs(DEFAULT_TIMEOUT_SECONDS),
        chain_id.to_owned(),
    )
    .with_signers_manager(Arc::new(signers_manager))
    .with_audit_writer(audit_writer);

    ContextRuleManager::new(config)
}

fn sa_error_result(err: &SaError) -> CallToolResult {
    let envelope = json!({
        "code": err.wire_code(),
        "message": err.to_string(),
    });
    let json_str = serde_json::to_string_pretty(&envelope).unwrap_or_else(|_| "{}".to_owned());
    let mut result = CallToolResult::success(vec![Content::text(json_str)]);
    result.is_error = Some(true);
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// WalletServer — approval-spine helper
// ─────────────────────────────────────────────────────────────────────────────

impl WalletServer {
    /// Persists a [`PendingApproval`] entry for a `stellar_rule_create`
    /// propose call.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn persist_rule_create_pending_approval(
        &self,
        smart_account: &str,
        network_passphrase: &str,
        chain_id: &str,
        definition: ContextRuleProposalSnapshot,
        proposal_sha256: [u8; 32],
        summary_line: String,
        profile_name: &str,
    ) -> Result<PendingApproval, String> {
        let approvals_dir = self
            .resolve_approval_dir()
            .map_err(|e| format!("approval dir resolution failed: {e}"))?;
        std::fs::create_dir_all(&approvals_dir)
            .map_err(|e| format!("approval dir create_all failed: {e}"))?;
        let store_path = approvals_dir.join(format!("{profile_name}.toml"));
        let mut store = open_with_retry(&store_path, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF)
            .map_err(|e| format!("approval store open failed: {e}"))?;

        let uid =
            process_uid_for_attestation().map_err(|e| format!("process UID unavailable: {e}"))?;
        let entry = PendingApproval::new_rule_proposal_pending(
            smart_account.to_owned(),
            network_passphrase.to_owned(),
            chain_id.to_owned(),
            definition,
            proposal_sha256,
            summary_line,
            uid,
            crate::tools::common::APPROVAL_TTL_MS,
        )
        .map_err(|e| format!("PendingApproval::new_rule_proposal_pending failed: {e}"))?;

        let now_ms = now_unix_ms()
            .map_err(|e| format!("approval store insert: current time unavailable: {e}"))?;
        store
            .insert(entry.clone(), now_ms)
            .map_err(|e| format!("approval store insert failed: {e}"))?;

        Ok(entry)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

#[mcp_tool_router]
#[tool_router(router = rule_create_tool_router, vis = "pub(crate)")]
impl WalletServer {
    /// Resolves and simulates an agent-proposed `add_context_rule`
    /// installation (propose step). Mints the domain-separated
    /// `proposal_sha256` digest and parks the FULLY RESOLVED rule
    /// definition as a `RuleProposalSimulated` pending approval.
    ///
    /// # Tool annotations
    ///
    /// - `readOnlyHint = false` — persists a pending-approval entry.
    /// - `destructiveHint = false` — does NOT install anything on-chain.
    ///
    /// # Errors
    ///
    /// Returns a tool-level error when `smart_account` is invalid, the
    /// context/signer/policy grammar is malformed, the wasm-hash pin check
    /// refuses (mutable/unknown contract, no override), or the simulate
    /// call fails.
    #[mcp_tool_item(
        name = "stellar_rule_create",
        destructive_hint = false,
        read_only_hint = false,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_rule_create",
        description = "Resolve and simulate an agent-proposed add_context_rule installation \
                       (propose step). Testnet-only — refuses chain_id=stellar:mainnet. \
                       Signers accept delegated (G/C-strkey), external (raw \
                       verifier+pubkey hex), or webauthn (passkey credential name, resolved to \
                       bytes at propose time). Policies accept raw (address+XDR) or \
                       spending_limit (typed). Returns {approval_nonce, expires_at_unix_ms, \
                       summary} — pass approval_nonce to stellar_rule_create_commit after the \
                       operator approves via `stellar-agent approve --id <nonce>`. \
                       destructive_hint=false; read_only_hint=false.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    async fn stellar_rule_create(
        &self,
        Parameters(args): Parameters<StellarRuleCreateArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // ── Mainnet write defence (structural, before any RPC call) ───────────
        if args.chain_id == "stellar:mainnet" {
            return Err(rmcp::ErrorData::invalid_params(
                "network.mainnet_write_forbidden: stellar_rule_create is testnet-only; \
                 rule-write authority changes are refused on mainnet",
                None,
            ));
        }

        // ── Parse smart_account ───────────────────────────────────────────────
        let smart_account = parse_c_strkey_to_smart_account(&args.smart_account).map_err(|e| {
            rmcp::ErrorData::invalid_params(
                format!("invalid smart_account (expected C-strkey): {e}"),
                None,
            )
        })?;

        // ── Parse context grammar (fail closed before any RPC call) ───────────
        let context = parse_rule_context_arg(&args.context)
            .map_err(|e| rmcp::ErrorData::invalid_params(e, None))?;
        let context_snapshot = context_type_to_snapshot(&context)
            .map_err(|e| rmcp::ErrorData::internal_error(e, None))?;

        // ── Name-length pre-flight ─────────────────────────────────────────────
        if args.name.is_empty() || args.name.len() > OZ_MAX_NAME_SIZE {
            return Err(rmcp::ErrorData::invalid_params(
                format!(
                    "name must be 1-{OZ_MAX_NAME_SIZE} bytes, got {} bytes",
                    args.name.len()
                ),
                None,
            ));
        }

        // ── Resolve signers (typed + snapshot, together) ──────────────────────
        let resolved_signers = resolve_signers(&args.signers, self)?;
        if !resolved_signers.has_delegated && !args.accept_no_delegated_fallback {
            return Err(rmcp::ErrorData::invalid_params(
                "validation.passkey_only_rule_no_delegated_fallback: this rule has no \
                 delegated (ed25519) fallback signer; if the authenticator device is lost \
                 the rule becomes permanently inaccessible. Pass \
                 accept_no_delegated_fallback=true to acknowledge.",
                None,
            ));
        }

        // ── Resolve policies (typed + snapshot, together) ─────────────────────
        let (policies_typed, policies_snapshot) =
            resolve_policies(&args.policies, &context, &self.profile.network_passphrase)?;

        if args.auth_rule_ids.is_empty() {
            return Err(rmcp::ErrorData::invalid_params(
                "auth_rule_ids must be non-empty",
                None,
            ));
        }
        let auth_rule_ids: Vec<stellar_agent_core::smart_account::rule_id::ContextRuleId> = args
            .auth_rule_ids
            .iter()
            .map(|id| stellar_agent_core::smart_account::rule_id::ContextRuleId::new(*id))
            .collect();

        let rule_definition = ContextRuleDefinition::new(
            context,
            args.name.clone(),
            args.valid_until,
            resolved_signers.typed,
            policies_typed,
        );

        // ── Dispatch gate ──────────────────────────────────────────────────────
        let args_value = json!({
            "chain_id": &args.chain_id,
            "smart_account": &args.smart_account,
            "name": &args.name,
        });
        let dispatch_outcome = self
            .dispatch_gate("stellar_rule_create", &args_value, &args.chain_id)
            .await?;

        // ── Simulate (runs the SAME pin check install_rule runs) ─────────────
        let manager = match build_write_context_rule_manager(self) {
            Ok(m) => m,
            Err(err) => {
                return Err(rmcp::ErrorData::internal_error(
                    format!("smart_account_manager_error: {err}"),
                    None,
                ));
            }
        };
        let source_g = self.profile.mcp_signer_default.account.clone();
        let request_id = uuid::Uuid::new_v4().to_string();
        let simulate_output = match manager
            .simulate_install_rule(
                smart_account.clone(),
                rule_definition.clone(),
                &source_g,
                args.accept_mutable_verifier,
                args.accept_unknown_verifier,
                request_id.clone(),
            )
            .await
        {
            Ok(o) => o,
            Err(err) => return Ok(sa_error_result(&err)),
        };

        // ── Compute the domain-separated proposal digest ──────────────────────
        let proposal_sha256 = match compute_context_rule_proposal_sha256(
            &smart_account,
            &rule_definition,
            &auth_rule_ids,
            args.accept_mutable_verifier,
            args.accept_unknown_verifier,
        ) {
            Ok(d) => d,
            Err(err) => {
                return Err(rmcp::ErrorData::internal_error(
                    format!("rule_proposal_digest_error: {err}"),
                    None,
                ));
            }
        };

        // ── Build the snapshot ─────────────────────────────────────────────────
        let context_label = rule_definition.context_type_label();
        let summary_line = format!(
            "{context_label} rule \"{name}\" with {signers} signer(s), {policies} \
             polic{plural}",
            name = args.name,
            signers = args.signers.len(),
            policies = args.policies.len(),
            plural = if args.policies.len() == 1 { "y" } else { "ies" },
        );
        let snapshot = ContextRuleProposalSnapshot::new(
            context_snapshot,
            args.name.clone(),
            args.valid_until,
            resolved_signers.snapshot,
            policies_snapshot,
            args.auth_rule_ids.clone(),
            args.accept_mutable_verifier,
            args.accept_unknown_verifier,
        );

        // ── Persist the pending approval — UNCONDITIONALLY ────────────────────
        //
        // Unlike `stellar_pay` / `stellar_claim` (which persist a pending
        // approval only when the policy engine returns `RequireApproval`,
        // since their commit step can otherwise proceed straight from a
        // caller-supplied `envelope_xdr`), `stellar_rule_create_commit` has
        // NO envelope fallback: the pending `RuleProposalSimulated` entry is
        // the SOLE carrier of the resolved rule definition. `approval_nonce`
        // is therefore always minted, regardless of `dispatch_outcome` — the
        // entry doubles as both the identity-carrier (always needed) and the
        // consent-token (verified at commit only when policy requires it).
        let requires_operator_approval =
            matches!(dispatch_outcome, DispatchOutcome::RequireApproval(_));
        let profile_name = self.profile_name_for_approval();
        let entry = self
            .persist_rule_create_pending_approval(
                &args.smart_account,
                &self.profile.network_passphrase,
                &args.chain_id,
                snapshot,
                proposal_sha256,
                summary_line.clone(),
                &profile_name,
            )
            .map_err(|e| {
                rmcp::ErrorData::internal_error(format!("approval.store_error: {e}"), None)
            })?;

        // ── Build response ─────────────────────────────────────────────────────
        let view = json!({
            "approval_nonce": entry.approval_nonce,
            "expires_at_unix_ms": entry.expires_at_unix_ms,
            "requires_operator_approval": requires_operator_approval,
            "proposal_sha256_hex": proposal_sha256.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "latest_ledger": simulate_output.latest_ledger,
            "pinned_verifier_wasm_hashes_first8": simulate_output.pin_result.pinned_verifier_hashes_first8(),
            "pinned_policy_wasm_hashes_first8": simulate_output.pin_result.pinned_policy_hashes_first8(),
            "mutable_override": simulate_output.pin_result.mutable_override,
            "unknown_override": simulate_output.pin_result.unknown_override,
            "summary": {
                "smart_account": &args.smart_account,
                "context_type_label": context_label,
                "name": &args.name,
                "valid_until": args.valid_until,
                "signer_count": args.signers.len(),
                "policy_count": args.policies.len(),
                "auth_rule_ids": &args.auth_rule_ids,
                "summary_line": &summary_line,
            },
        });
        let envelope = stellar_agent_core::envelope::Envelope::ok(view);
        let json_out = envelope
            .to_json_pretty()
            .unwrap_or_else(|_| String::from("{}"));
        Ok(CallToolResult::success(vec![Content::text(json_out)]))
    }

    /// Verifies the operator's attestation and installs the proposed context
    /// rule (commit step).
    ///
    /// # Security invariants
    ///
    /// 1. The pending `RuleProposalSimulated` entry (looked up by
    ///    `approval_nonce`) is the SOLE source of the rule definition —
    ///    never caller-supplied args.
    /// 2. A DEDICATED gate (`PendingApprovalStore::verify_rule_proposal_gate`)
    ///    verifies the HMAC attestation over `proposal_sha256` — the shared
    ///    pay/claim `verify_attestation_gate` is NOT used.
    /// 3. The digest is recomputed from the stored snapshot through the SAME
    ///    builder (`compute_context_rule_proposal_sha256`) used at propose
    ///    time, UNCONDITIONALLY (even on a policy-engine `Allow` outcome) —
    ///    a mismatch against the entry's own recorded digest is
    ///    `simulation.divergence` (store self-consistency, independent of
    ///    the operator-consent question).
    /// 4. `install_rule` (unchanged) then runs its own full
    ///    divergence/pin/auth machinery and submits.
    ///
    /// # Tool annotations
    ///
    /// - `readOnlyHint = false` — signs and submits.
    /// - `destructiveHint = true` — installs a rule on-chain.
    #[mcp_tool_item(
        name = "stellar_rule_create_commit",
        destructive_hint = true,
        read_only_hint = false,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_rule_create_commit",
        description = "Verify the operator's attestation and install the proposed context rule \
                       (commit step). Testnet-only — refuses chain_id=stellar:mainnet. ALWAYS \
                       requires operator attestation, regardless of the \
                       policy engine's verdict for this call — the agent never holds rule-write \
                       authority. Requires the approval_nonce from stellar_rule_create and \
                       approval_attestation. Returns {rule_id, tx_hash}. destructive_hint=true; \
                       read_only_hint=false.",
        annotations(read_only_hint = false, destructive_hint = true)
    )]
    async fn stellar_rule_create_commit(
        &self,
        Parameters(args): Parameters<StellarRuleCreateCommitArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // SECURITY: unlike a payment, where an engine `Allow` verdict spends
        // within an operator-configured budget, a rule-create `Allow` would
        // let the agent grant ITSELF permanent — potentially account-wide —
        // authority. This feature's contract is that the agent NEVER holds
        // rule-write authority, so the public entry point forces
        // `RequireApproval` UNCONDITIONALLY, exactly as the toolset-gated
        // wrapper (`invoke_stellar_rule_create_commit_toolset_gated`) does.
        // An engine `Allow` can never skip operator attestation for this
        // tool; only a genuine engine `RequireApproval` (passed through
        // as-is, using its own real nonce/ttl) or this forced override ever
        // reaches the commit path.
        let forced = DispatchOutcome::RequireApproval(
            stellar_agent_core::policy::ApprovalRequest::new(args.approval_nonce.clone(), 86_400),
        );
        self.stellar_rule_create_commit_impl(args, Some(forced))
            .await
    }

    /// Inner implementation of `stellar_rule_create_commit`.
    ///
    /// Separated so BOTH call sites — the public tool handler
    /// (`stellar_rule_create_commit`) and the toolset-gated path
    /// (`invoke_stellar_rule_create_commit_toolset_gated`) — supply a
    /// forced `DispatchOutcome::RequireApproval` override, mirroring
    /// `stellar_pay_commit_impl` (pay.rs:1135)'s override PLUMBING, but with
    /// a DELIBERATE divergence from the pay precedent: `forced_dispatch_outcome`
    /// is `Some(..)` at EVERY call site here, never `None`. A payment `Allow`
    /// spends within an operator-configured budget; a rule-create `Allow`
    /// would let the agent grant itself permanent (potentially
    /// account-wide) authority, which this feature's contract forbids.
    ///
    /// # Security
    ///
    /// The forced override is the load-bearing per-action-approval
    /// mechanism for EVERY caller of this tool, not just toolset-routed
    /// ones. An engine `Allow` verdict can never itself authorize an
    /// install; only a genuine engine `RequireApproval` or this forced
    /// override ever reaches the commit path.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn stellar_rule_create_commit_impl(
        &self,
        args: StellarRuleCreateCommitArgs,
        forced_dispatch_outcome: Option<DispatchOutcome>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        use crate::tools::common::approval_required_indistinguishable;

        // ── Mainnet write defence (defense in depth) ──────────────────────────
        // Does NOT rely solely on stellar_rule_create's propose-time refusal:
        // this commit call's chain_id is caller-supplied and independent of
        // whatever chain_id the (possibly different) propose call used.
        if args.chain_id == "stellar:mainnet" {
            return Err(rmcp::ErrorData::invalid_params(
                "network.mainnet_write_forbidden: stellar_rule_create_commit is testnet-only; \
                 rule-write authority changes are refused on mainnet",
                None,
            ));
        }

        // ── Dispatch gate ──────────────────────────────────────────────────────
        let args_value = json!({
            "chain_id": &args.chain_id,
            "approval_nonce": &args.approval_nonce,
        });
        let dispatch_outcome = match forced_dispatch_outcome {
            Some(forced) => match self
                .dispatch_gate("stellar_rule_create_commit", &args_value, &args.chain_id)
                .await?
            {
                DispatchOutcome::Allow => {
                    tracing::debug!(
                        tool = "stellar_rule_create_commit",
                        "toolset_gated: overriding DispatchOutcome::Allow → forced RequireApproval"
                    );
                    forced
                }
                other => other,
            },
            None => {
                self.dispatch_gate("stellar_rule_create_commit", &args_value, &args.chain_id)
                    .await?
            }
        };

        // ── Load the pending entry (the SOLE source of the definition) ───────
        let approvals_dir = self.resolve_approval_dir().map_err(|_| {
            tracing::debug!(
                tool = "stellar_rule_create_commit",
                "approval dir resolution failed"
            );
            approval_required_indistinguishable()
        })?;
        let store_path = approvals_dir.join(format!("{}.toml", self.profile_name_for_approval()));
        let mut store = open_with_retry(&store_path, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF)
            .map_err(|_| {
                tracing::debug!(
                    tool = "stellar_rule_create_commit",
                    "approval store open failed"
                );
                approval_required_indistinguishable()
            })?;

        let entry = store
            .get(&args.approval_nonce)
            .cloned()
            .ok_or_else(approval_required_indistinguishable)?;

        let now_ms = now_unix_ms()
            .map_err(|e| rmcp::ErrorData::internal_error(format!("clock_error: {e}"), None))?;
        if entry.is_expired(now_ms) {
            tracing::debug!(
                tool = "stellar_rule_create_commit",
                "approval entry expired"
            );
            return Err(approval_required_indistinguishable());
        }

        let (smart_account_str, entry_chain_id, definition_snapshot, stored_proposal_sha256) =
            match &entry.kind {
                stellar_agent_core::approval::ApprovalKind::Rejected { .. } => {
                    return Err(approval_rejected_error());
                }
                stellar_agent_core::approval::ApprovalKind::RuleProposalSimulated {
                    smart_account,
                    chain_id,
                    definition,
                    proposal_sha256,
                    ..
                } => (
                    smart_account.clone(),
                    chain_id.clone(),
                    definition.clone(),
                    *proposal_sha256,
                ),
                _ => return Err(approval_required_indistinguishable()),
            };

        if entry_chain_id != args.chain_id {
            return Err(rmcp::ErrorData::internal_error(
                "simulation.divergence: pending approval was proposed for a different chain_id",
                None,
            ));
        }

        // ── Reconstruct the definition and recompute the digest ──────────────
        // UNCONDITIONAL (regardless of dispatch_outcome): a store-self-
        // consistency check, independent of the operator-consent question.
        let smart_account = parse_c_strkey_to_smart_account(&smart_account_str).map_err(|e| {
            rmcp::ErrorData::internal_error(
                format!("simulation.divergence: stored smart_account invalid: {e}"),
                None,
            )
        })?;
        let rule_definition =
            context_rule_definition_from_snapshot(&definition_snapshot).map_err(|e| {
                rmcp::ErrorData::internal_error(
                    format!("simulation.divergence: snapshot reconstruction failed: {e}"),
                    None,
                )
            })?;
        let auth_rule_ids: Vec<stellar_agent_core::smart_account::rule_id::ContextRuleId> =
            definition_snapshot
                .auth_rule_ids
                .iter()
                .map(|id| stellar_agent_core::smart_account::rule_id::ContextRuleId::new(*id))
                .collect();

        let recomputed_digest = compute_context_rule_proposal_sha256(
            &smart_account,
            &rule_definition,
            &auth_rule_ids,
            definition_snapshot.accept_mutable_verifier,
            definition_snapshot.accept_unknown_verifier,
        )
        .map_err(|e| {
            rmcp::ErrorData::internal_error(format!("rule_proposal_digest_error: {e}"), None)
        })?;

        if recomputed_digest != stored_proposal_sha256 {
            return Err(rmcp::ErrorData::internal_error(
                "simulation.divergence: recomputed digest does not match the entry's own \
                 recorded proposal_sha256",
                None,
            ));
        }

        // ── Dedicated attestation gate (skipped on Allow, mirroring \
        //    verify_attestation_gate's no-op-on-Allow semantics) ──────────────
        if let DispatchOutcome::RequireApproval(_) = dispatch_outcome {
            let (nonce_str, attestation_b64) = match args.approval_attestation.as_deref() {
                Some(a) => (args.approval_nonce.as_str(), a),
                None => {
                    tracing::debug!(
                        tool = "stellar_rule_create_commit",
                        "approval_attestation absent"
                    );
                    return Err(approval_required_indistinguishable());
                }
            };
            let attestation_bytes: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(attestation_b64)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| {
                    tracing::debug!(
                        tool = "stellar_rule_create_commit",
                        "attestation base64 decode failed"
                    );
                    approval_required_indistinguishable()
                })?;

            let attestation_key_bytes = load_attestation_key(&self.profile)?;
            let attestation_key = zeroize::Zeroizing::new(attestation_key_bytes);

            store
                .verify_rule_proposal_gate(
                    nonce_str,
                    &recomputed_digest,
                    &attestation_key,
                    &attestation_bytes,
                    now_ms,
                )
                .map_err(|e| match e {
                    RuleProposalGateError::Rejected => approval_rejected_error(),
                    // `RuleProposalGateError` is `#[non_exhaustive]`; a future
                    // variant collapses to the same indistinguishable refusal
                    // as `Refused` (fail-closed default).
                    _ => {
                        tracing::debug!(
                            tool = "stellar_rule_create_commit",
                            "verify_rule_proposal_gate refused"
                        );
                        approval_required_indistinguishable()
                    }
                })?;
        }

        // ── Load signer + build the write-capable manager ─────────────────────
        let source_g = self.profile.mcp_signer_default.account.clone();
        let handle = match signer_from_keyring(&self.profile.mcp_signer_default, &source_g).await {
            Ok(h) => h,
            Err(err) => {
                let envelope = stellar_agent_core::envelope::Envelope::<()>::err(&err);
                let json = envelope
                    .to_json_pretty()
                    .unwrap_or_else(|_| String::from("{}"));
                let mut result = CallToolResult::success(vec![Content::text(json)]);
                result.is_error = Some(true);
                return Ok(result);
            }
        };

        let manager = match build_write_context_rule_manager(self) {
            Ok(m) => m,
            Err(err) => {
                return Err(rmcp::ErrorData::internal_error(
                    format!("smart_account_manager_error: {err}"),
                    None,
                ));
            }
        };

        let request_id = uuid::Uuid::new_v4().to_string();
        let install_result = manager
            .install_rule(
                smart_account,
                rule_definition,
                auth_rule_ids,
                &handle,
                None,
                request_id,
                definition_snapshot.accept_mutable_verifier,
                definition_snapshot.accept_unknown_verifier,
            )
            .await;

        match install_result {
            Ok(output) => {
                tracing::info!(
                    tool = "stellar_rule_create_commit",
                    chain = %args.chain_id,
                    rule_id = output.rule_id,
                    decision = "committed",
                    "stellar_rule_create_commit: rule installed"
                );

                // Best-effort removal of the consumed approval entry.
                if let Err(e) = store.remove(&args.approval_nonce) {
                    tracing::warn!(
                        nonce = %args.approval_nonce,
                        error = %e,
                        "stellar_rule_create_commit: approval entry remove failed after \
                         successful install; entry will expire via gc"
                    );
                }

                let view = json!({
                    "rule_id": output.rule_id,
                    "tx_hash": output.tx_hash,
                });
                let envelope = stellar_agent_core::envelope::Envelope::ok(view);
                let json_out = envelope
                    .to_json_pretty()
                    .unwrap_or_else(|_| String::from("{}"));
                Ok(CallToolResult::success(vec![Content::text(json_out)]))
            }
            Err(err) => Ok(sa_error_result(&err)),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Toolset-dispatch helpers
// ─────────────────────────────────────────────────────────────────────────────

impl WalletServer {
    /// Invoke `stellar_rule_create` (propose step) by value, bypassing the
    /// rmcp transport layer. Used by the toolset-invocation routing path
    /// (`tools/toolsets.rs`) — granted by `Capability::ProposeTransaction`
    /// (ungated), mirroring `stellar_pay` / `stellar_claim`.
    ///
    /// # Errors
    ///
    /// Same as [`WalletServer::stellar_rule_create`].
    pub(crate) async fn invoke_stellar_rule_create(
        &self,
        args: StellarRuleCreateArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_rule_create(Parameters(args)).await
    }

    /// Routes to `stellar_rule_create_commit` with the per-action
    /// `RuleProposalSimulated` approval FORCED ON UNCONDITIONALLY — mirrors
    /// `invoke_stellar_pay_commit_toolset_gated` (pay.rs:1654).
    ///
    /// Unlike the pay/claim toolset-gated wrappers, no "synthesise a fresh
    /// pending approval if the agent doesn't already have one" branch is
    /// needed here: `stellar_rule_create` ALWAYS persists a
    /// `RuleProposalSimulated` entry regardless of the propose-time policy
    /// outcome (`approval_nonce` is a REQUIRED field with no `envelope_xdr`
    /// fallback — see [`StellarRuleCreateCommitArgs`] docs), so
    /// `args.approval_nonce` always refers to a real entry by construction.
    ///
    /// # Errors
    ///
    /// Same as [`WalletServer::stellar_rule_create_commit`].
    pub(crate) async fn invoke_stellar_rule_create_commit_toolset_gated(
        &self,
        args: StellarRuleCreateCommitArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let forced = DispatchOutcome::RequireApproval(
            stellar_agent_core::policy::ApprovalRequest::new(args.approval_nonce.clone(), 86_400),
        );
        self.stellar_rule_create_commit_impl(args, Some(forced))
            .await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "test-helpers"))]
impl WalletServer {
    /// Calls `stellar_rule_create` with the given args, bypassing the rmcp
    /// transport.
    #[doc(hidden)]
    pub async fn call_stellar_rule_create(
        &self,
        args: StellarRuleCreateArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_rule_create(Parameters(args)).await
    }

    /// Calls `stellar_rule_create_commit` with the given args, bypassing the
    /// rmcp transport.
    #[doc(hidden)]
    pub async fn call_stellar_rule_create_commit(
        &self,
        args: StellarRuleCreateCommitArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_rule_create_commit(Parameters(args)).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests: arg schema round-trips + grammar parsing
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use super::*;

    #[test]
    fn stellar_rule_create_args_deserialise_minimal() {
        let json = serde_json::json!({
            "chain_id": "stellar:testnet",
            "smart_account": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "name": "spend-daily",
            "signers": [
                {"kind": "delegated", "address": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
            ],
        });
        let args: StellarRuleCreateArgs = serde_json::from_value(json).expect("deserialise");
        assert_eq!(args.context, "default");
        assert_eq!(args.auth_rule_ids, vec![0]);
        assert!(args.policies.is_empty());
        assert!(!args.accept_mutable_verifier);
    }

    #[test]
    fn stellar_rule_create_commit_args_requires_approval_nonce() {
        let json = serde_json::json!({
            "chain_id": "stellar:testnet",
        });
        let result: Result<StellarRuleCreateCommitArgs, _> = serde_json::from_value(json);
        assert!(result.is_err(), "approval_nonce must be required");
    }

    #[test]
    fn stellar_rule_create_commit_args_attestation_optional() {
        let json = serde_json::json!({
            "chain_id": "stellar:testnet",
            "approval_nonce": "AAAAAAAAAAAAAAAAAAAAAA",
        });
        let args: StellarRuleCreateCommitArgs = serde_json::from_value(json).expect("deserialise");
        assert!(args.approval_attestation.is_none());
    }

    // ── --context grammar ─────────────────────────────────────────────────────

    #[test]
    fn context_grammar_default() {
        assert!(matches!(
            parse_rule_context_arg("default").unwrap(),
            RuleContext::Default
        ));
    }

    #[test]
    fn context_grammar_call_contract() {
        let ctx = parse_rule_context_arg(
            "call-contract:CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        )
        .unwrap();
        assert!(matches!(ctx, RuleContext::CallContract { .. }));
    }

    #[test]
    fn context_grammar_create_contract() {
        let ctx = parse_rule_context_arg(&format!("create-contract:{}", "ab".repeat(32))).unwrap();
        assert!(matches!(ctx, RuleContext::CreateContract { .. }));
    }

    #[test]
    fn context_grammar_rejects_unknown() {
        assert!(parse_rule_context_arg("bogus").is_err());
    }

    #[test]
    fn context_grammar_rejects_short_wasm_hash() {
        assert!(parse_rule_context_arg("create-contract:abcd").is_err());
    }

    // ── Signer arg tagged-enum round trips ────────────────────────────────────

    #[test]
    fn signer_arg_delegated_round_trip() {
        let json = serde_json::json!({"kind": "delegated", "address": "GAAA"});
        let arg: RuleCreateSignerArg = serde_json::from_value(json).unwrap();
        assert!(matches!(arg, RuleCreateSignerArg::Delegated { .. }));
    }

    #[test]
    fn signer_arg_webauthn_round_trip() {
        let json = serde_json::json!({"kind": "webauthn", "credential_name": "my-key"});
        let arg: RuleCreateSignerArg = serde_json::from_value(json).unwrap();
        assert!(matches!(arg, RuleCreateSignerArg::Webauthn { .. }));
    }

    #[test]
    fn policy_arg_spending_limit_round_trip() {
        let json = serde_json::json!({
            "kind": "spending_limit",
            "limit_stroops": "10000000",
            "period_ledgers": 17_280,
        });
        let arg: RuleCreatePolicyArg = serde_json::from_value(json).unwrap();
        assert!(matches!(arg, RuleCreatePolicyArg::SpendingLimit { .. }));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The tests below exercise the resolution/validation logic and the
    // commit-side gate-refusal paths in this file
    // — the resolution/validation logic and the commit-side gate-refusal
    // paths, all of which fire before any RPC round-trip and so require no
    // wiremock server.
    // ─────────────────────────────────────────────────────────────────────────

    use stellar_agent_core::approval::{DEFAULT_TTL_MS, PendingApprovalStore};
    use stellar_agent_core::profile::schema::Profile;

    const TEST_G: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
    const TEST_G_2: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
    const TEST_C: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
    const TEST_SMART_ACCOUNT: &str = "CC53XO53XO53XO53XO53XO53XO53XO53XO53XO53XO53XO53XO53WQD5";

    /// A `WalletServer` with a `Noop` policy engine (so no signed policy file
    /// is required) whose `mcp_signer_default.account` is [`TEST_G`] — the
    /// identity `resolve_signers` compares `Delegated` addresses against for
    /// the `is_proposer` tag.
    fn test_server() -> WalletServer {
        let mut profile = Profile::builder_testnet("svc", TEST_G, "n-svc", "n-acct")
            .with_noop_engine()
            .build();
        profile.rpc_url = "http://127.0.0.1:1".to_owned();
        WalletServer::new(profile).expect("WalletServer::new must not fail")
    }

    // ── context_type_to_snapshot ──────────────────────────────────────────────

    #[test]
    fn context_type_to_snapshot_default() {
        let snapshot = context_type_to_snapshot(&RuleContext::Default).unwrap();
        assert_eq!(snapshot, RuleProposalContextType::Default);
    }

    #[test]
    fn context_type_to_snapshot_call_contract_round_trips_strkey() {
        let ctx = parse_rule_context_arg(&format!("call-contract:{TEST_SMART_ACCOUNT}")).unwrap();
        let snapshot = context_type_to_snapshot(&ctx).unwrap();
        match snapshot {
            RuleProposalContextType::CallContract { contract } => {
                assert_eq!(contract, TEST_SMART_ACCOUNT);
            }
            other => panic!("expected CallContract, got {other:?}"),
        }
    }

    #[test]
    fn context_type_to_snapshot_create_contract_round_trips_hex() {
        let hex_hash = "ab".repeat(32);
        let ctx = parse_rule_context_arg(&format!("create-contract:{hex_hash}")).unwrap();
        let snapshot = context_type_to_snapshot(&ctx).unwrap();
        match snapshot {
            RuleProposalContextType::CreateContract { wasm_hash_hex } => {
                assert_eq!(wasm_hash_hex, hex_hash);
            }
            other => panic!("expected CreateContract, got {other:?}"),
        }
    }

    // ── resolve_signers ────────────────────────────────────────────────────────

    #[test]
    fn resolve_signers_rejects_empty() {
        let server = test_server();
        let err = resolve_signers(&[], &server).unwrap_err();
        assert!(err.message.contains("non-empty"));
    }

    #[test]
    fn resolve_signers_rejects_over_oz_max_signers() {
        let server = test_server();
        let signers: Vec<RuleCreateSignerArg> = (0..=OZ_MAX_SIGNERS)
            .map(|_| RuleCreateSignerArg::Delegated {
                address: TEST_G.to_owned(),
            })
            .collect();
        let err = resolve_signers(&signers, &server).unwrap_err();
        assert!(err.message.contains("MAX_SIGNERS"));
    }

    #[test]
    fn resolve_signers_delegated_tags_proposer_when_address_matches_profile() {
        let server = test_server();
        let signers = vec![RuleCreateSignerArg::Delegated {
            address: TEST_G.to_owned(),
        }];
        let resolved = resolve_signers(&signers, &server).unwrap();
        assert!(resolved.has_delegated);
        assert_eq!(resolved.snapshot.len(), 1);
        assert!(
            resolved.snapshot[0].is_proposer,
            "the agent's own signing address must be tagged as proposer"
        );
    }

    #[test]
    fn resolve_signers_delegated_does_not_tag_proposer_for_a_different_address() {
        let server = test_server();
        let signers = vec![RuleCreateSignerArg::Delegated {
            address: TEST_G_2.to_owned(),
        }];
        let resolved = resolve_signers(&signers, &server).unwrap();
        assert!(!resolved.snapshot[0].is_proposer);
    }

    #[test]
    fn resolve_signers_delegated_accepts_c_strkey() {
        let server = test_server();
        let signers = vec![RuleCreateSignerArg::Delegated {
            address: TEST_SMART_ACCOUNT.to_owned(),
        }];
        let resolved = resolve_signers(&signers, &server).unwrap();
        assert_eq!(resolved.snapshot.len(), 1);
        assert!(!resolved.snapshot[0].is_proposer);
    }

    #[test]
    fn resolve_signers_delegated_rejects_invalid_strkey() {
        let server = test_server();
        let signers = vec![RuleCreateSignerArg::Delegated {
            address: "not-a-strkey".to_owned(),
        }];
        let err = resolve_signers(&signers, &server).unwrap_err();
        assert!(err.message.contains("invalid G/C-strkey"));
    }

    #[test]
    fn resolve_signers_external_valid() {
        let server = test_server();
        let signers = vec![RuleCreateSignerArg::External {
            verifier: TEST_C.to_owned(),
            pubkey_data_hex: "ab".repeat(65),
        }];
        let resolved = resolve_signers(&signers, &server).unwrap();
        assert!(!resolved.has_delegated);
        assert!(!resolved.snapshot[0].is_proposer);
        assert_eq!(
            resolved.snapshot[0].pubkey_data.as_ref().map(Vec::len),
            Some(65)
        );
    }

    #[test]
    fn resolve_signers_external_rejects_invalid_verifier_strkey() {
        let server = test_server();
        let signers = vec![RuleCreateSignerArg::External {
            verifier: "not-a-strkey".to_owned(),
            pubkey_data_hex: "ab".repeat(65),
        }];
        let err = resolve_signers(&signers, &server).unwrap_err();
        assert!(err.message.contains("verifier"));
    }

    #[test]
    fn resolve_signers_external_rejects_invalid_hex() {
        let server = test_server();
        let signers = vec![RuleCreateSignerArg::External {
            verifier: TEST_C.to_owned(),
            pubkey_data_hex: "not-hex!!".to_owned(),
        }];
        let err = resolve_signers(&signers, &server).unwrap_err();
        assert!(err.message.contains("invalid hex"));
    }

    #[test]
    fn resolve_signers_external_rejects_oversized_pubkey() {
        let server = test_server();
        let signers = vec![RuleCreateSignerArg::External {
            verifier: TEST_C.to_owned(),
            pubkey_data_hex: "ab".repeat(OZ_MAX_EXTERNAL_KEY_SIZE + 1),
        }];
        let err = resolve_signers(&signers, &server).unwrap_err();
        assert!(err.message.contains("MAX_EXTERNAL_KEY_SIZE"));
    }

    // ── resolve_policies ───────────────────────────────────────────────────────

    const NETWORK_PASSPHRASE: &str = "Test SDF Network ; September 2015";

    #[test]
    fn resolve_policies_empty_is_ok() {
        let (typed, snapshot) = resolve_policies(&[], &RuleContext::Default, NETWORK_PASSPHRASE)
            .expect("empty policies must be accepted");
        assert!(typed.is_empty());
        assert!(snapshot.is_empty());
    }

    #[test]
    fn resolve_policies_rejects_over_oz_max_policies() {
        let policies: Vec<RuleCreatePolicyArg> = (0..=OZ_MAX_POLICIES)
            .map(|_| RuleCreatePolicyArg::Raw {
                policy_address: TEST_C.to_owned(),
                install_param_xdr_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(b"x"),
            })
            .collect();
        let err =
            resolve_policies(&policies, &RuleContext::Default, NETWORK_PASSPHRASE).unwrap_err();
        assert!(err.message.contains("MAX_POLICIES"));
    }

    #[test]
    fn resolve_policies_raw_rejects_invalid_base64() {
        let policies = vec![RuleCreatePolicyArg::Raw {
            policy_address: TEST_C.to_owned(),
            install_param_xdr_b64: "not valid base64!!".to_owned(),
        }];
        let err =
            resolve_policies(&policies, &RuleContext::Default, NETWORK_PASSPHRASE).unwrap_err();
        assert!(err.message.contains("not valid base64url"));
    }

    #[test]
    fn resolve_policies_raw_rejects_invalid_xdr() {
        let policies = vec![RuleCreatePolicyArg::Raw {
            policy_address: TEST_C.to_owned(),
            install_param_xdr_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(b"not a valid ScVal encoding at all, much too long for any tag"),
        }];
        let err =
            resolve_policies(&policies, &RuleContext::Default, NETWORK_PASSPHRASE).unwrap_err();
        assert!(err.message.contains("XDR decode failed"));
    }

    #[test]
    fn resolve_policies_raw_valid_passes_through() {
        let param_bytes = ScVal::U32(7).to_xdr(Limits::none()).expect("encode");
        let param = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(param_bytes);
        let policies = vec![RuleCreatePolicyArg::Raw {
            policy_address: TEST_C.to_owned(),
            install_param_xdr_b64: param,
        }];
        let (typed, snapshot) =
            resolve_policies(&policies, &RuleContext::Default, NETWORK_PASSPHRASE)
                .expect("valid raw ScVal must be accepted");
        assert_eq!(typed.len(), 1);
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].policy_address, TEST_C);
    }

    #[test]
    fn resolve_policies_spending_limit_rejects_non_call_contract_context() {
        let policies = vec![RuleCreatePolicyArg::SpendingLimit {
            limit_stroops: "10000000".to_owned(),
            period_ledgers: 17_280,
            policy_address: Some(TEST_C.to_owned()),
        }];
        // Default context (not CallContract) — OZ install rejects this with
        // OnlyCallContractAllowed; the client-side pre-flight must catch it
        // before ever reaching install_rule.
        let err =
            resolve_policies(&policies, &RuleContext::Default, NETWORK_PASSPHRASE).unwrap_err();
        assert!(err.message.to_lowercase().contains("callcontract"));
    }

    #[test]
    fn resolve_policies_spending_limit_rejects_zero_limit() {
        let ctx = parse_rule_context_arg(&format!("call-contract:{TEST_SMART_ACCOUNT}")).unwrap();
        let policies = vec![RuleCreatePolicyArg::SpendingLimit {
            limit_stroops: "0".to_owned(),
            period_ledgers: 17_280,
            policy_address: Some(TEST_C.to_owned()),
        }];
        let err = resolve_policies(&policies, &ctx, NETWORK_PASSPHRASE).unwrap_err();
        assert!(err.message.contains("positive"));
    }

    #[test]
    fn resolve_policies_spending_limit_rejects_zero_period() {
        let ctx = parse_rule_context_arg(&format!("call-contract:{TEST_SMART_ACCOUNT}")).unwrap();
        let policies = vec![RuleCreatePolicyArg::SpendingLimit {
            limit_stroops: "10000000".to_owned(),
            period_ledgers: 0,
            policy_address: Some(TEST_C.to_owned()),
        }];
        let err = resolve_policies(&policies, &ctx, NETWORK_PASSPHRASE).unwrap_err();
        assert!(err.message.contains("non-zero"));
    }

    #[test]
    fn resolve_policies_spending_limit_rejects_non_decimal_limit() {
        let ctx = parse_rule_context_arg(&format!("call-contract:{TEST_SMART_ACCOUNT}")).unwrap();
        let policies = vec![RuleCreatePolicyArg::SpendingLimit {
            limit_stroops: "not-a-number".to_owned(),
            period_ledgers: 17_280,
            policy_address: Some(TEST_C.to_owned()),
        }];
        let err = resolve_policies(&policies, &ctx, NETWORK_PASSPHRASE).unwrap_err();
        assert!(err.message.contains("not a valid decimal i128"));
    }

    #[test]
    fn resolve_policies_spending_limit_with_explicit_address_succeeds() {
        // An explicit policy_address bypasses the VerifierRegistry lookup
        // entirely, so this is hermetic (no ~/.config dependency).
        let ctx = parse_rule_context_arg(&format!("call-contract:{TEST_SMART_ACCOUNT}")).unwrap();
        let policies = vec![RuleCreatePolicyArg::SpendingLimit {
            limit_stroops: "10000000".to_owned(),
            period_ledgers: 17_280,
            policy_address: Some(TEST_C.to_owned()),
        }];
        let (typed, snapshot) =
            resolve_policies(&policies, &ctx, NETWORK_PASSPHRASE).expect("must succeed");
        assert_eq!(typed.len(), 1);
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].policy_address, TEST_C);
    }

    // ── stellar_rule_create_commit_impl: gate-refusal paths ───────────────────
    //
    // Every scenario below fires before `signer_from_keyring` / `install_rule`
    // are ever reached, so none requires a wiremock RPC server.

    fn valid_rule_definition_snapshot() -> ContextRuleProposalSnapshot {
        ContextRuleProposalSnapshot::new(
            RuleProposalContextType::Default,
            "spend-daily".to_owned(),
            None,
            vec![RuleProposalSigner::delegated(TEST_G.to_owned(), true)],
            vec![],
            vec![0],
            false,
            false,
        )
    }

    /// Computes the digest a genuine propose call would store for
    /// [`valid_rule_definition_snapshot`] against `smart_account`, so gate
    /// tests that must pass the digest-consistency check can use a value that
    /// genuinely matches (rather than an arbitrary placeholder).
    fn matching_digest_for(smart_account: &stellar_xdr::ScAddress) -> [u8; 32] {
        let rule_definition =
            context_rule_definition_from_snapshot(&valid_rule_definition_snapshot())
                .expect("reconstruct");
        let auth_rule_ids = vec![stellar_agent_core::smart_account::rule_id::ContextRuleId::new(0)];
        compute_context_rule_proposal_sha256(
            smart_account,
            &rule_definition,
            &auth_rule_ids,
            false,
            false,
        )
        .expect("digest compute")
    }

    /// Inserts a `RuleProposalSimulated` entry (with a genuinely-matching
    /// digest, unless `digest` overrides it) into a fresh store under
    /// `server`'s test approval dir, and returns its nonce.
    fn insert_rule_proposal_entry(
        server: &WalletServer,
        chain_id: &str,
        digest_override: Option<[u8; 32]>,
        ttl_ms: u64,
    ) -> String {
        let smart_account = parse_c_strkey_to_smart_account(TEST_SMART_ACCOUNT).unwrap();
        let digest = digest_override.unwrap_or_else(|| matching_digest_for(&smart_account));
        let approvals_dir = server.resolve_approval_dir().unwrap();
        let store_path = approvals_dir.join(format!("{}.toml", server.profile_name_for_approval()));
        let mut store = PendingApprovalStore::open(store_path).unwrap();
        let entry = PendingApproval::new_rule_proposal_pending(
            TEST_SMART_ACCOUNT.to_owned(),
            NETWORK_PASSPHRASE.to_owned(),
            chain_id.to_owned(),
            valid_rule_definition_snapshot(),
            digest,
            "Default rule \"spend-daily\"".to_owned(),
            process_uid_for_attestation().unwrap(),
            ttl_ms,
        )
        .unwrap();
        let nonce = entry.approval_nonce.clone();
        let now_ms = now_unix_ms().unwrap();
        store.insert(entry, now_ms).unwrap();
        nonce
    }

    fn commit_args(chain_id: &str, approval_nonce: String) -> StellarRuleCreateCommitArgs {
        StellarRuleCreateCommitArgs {
            chain_id: chain_id.to_owned(),
            approval_nonce,
            approval_attestation: None,
        }
    }

    #[tokio::test]
    async fn commit_unknown_nonce_is_indistinguishable_approval_required() {
        let mut server = test_server();
        let dir = tempfile::tempdir().unwrap();
        server.set_approval_dir_for_test(dir.path().to_path_buf());

        let result = server
            .call_stellar_rule_create_commit(commit_args(
                "stellar:testnet",
                "unknown-nonce".to_owned(),
            ))
            .await;
        let err = result.expect_err("unknown nonce must be Err");
        assert!(err.message.contains("policy.approval_required"));
    }

    #[tokio::test]
    async fn commit_expired_entry_is_indistinguishable_approval_required() {
        let mut server = test_server();
        let dir = tempfile::tempdir().unwrap();
        server.set_approval_dir_for_test(dir.path().to_path_buf());

        let nonce = insert_rule_proposal_entry(&server, "stellar:testnet", None, 0);
        let result = server
            .call_stellar_rule_create_commit(commit_args("stellar:testnet", nonce))
            .await;
        let err = result.expect_err("expired entry must be Err");
        assert!(err.message.contains("policy.approval_required"));
    }

    #[tokio::test]
    async fn commit_rejected_tombstone_returns_distinguishable_rejected() {
        let mut server = test_server();
        let dir = tempfile::tempdir().unwrap();
        server.set_approval_dir_for_test(dir.path().to_path_buf());

        let nonce = insert_rule_proposal_entry(&server, "stellar:testnet", None, DEFAULT_TTL_MS);
        // Reject it — leaves a Rejected tombstone under the same nonce.
        let approvals_dir = server.resolve_approval_dir().unwrap();
        let store_path = approvals_dir.join(format!("{}.toml", server.profile_name_for_approval()));
        let mut store = PendingApprovalStore::open(store_path).unwrap();
        store
            .reject(&nonce, now_unix_ms().unwrap(), DEFAULT_TTL_MS)
            .expect("reject must succeed on a live entry");
        drop(store);

        let result = server
            .call_stellar_rule_create_commit(commit_args("stellar:testnet", nonce))
            .await;
        let err = result.expect_err("rejected tombstone must be Err");
        assert!(
            err.message.contains("policy.approval_rejected"),
            "a live Rejected tombstone must be distinguishable, got: {}",
            err.message
        );
    }

    /// SECURITY regression guard: the PUBLIC `stellar_rule_create_commit`
    /// handler forces `RequireApproval` UNCONDITIONALLY, so even a policy
    /// engine that returns `Allow` (like `test_server()`'s `Noop` engine on
    /// testnet) can never let a commit through without operator attestation.
    /// This is a deliberate divergence from the payment/claim precedent,
    /// where an engine `Allow` on the commit tool DOES bypass the
    /// attestation requirement — a rule-create `Allow` would otherwise let
    /// the agent grant itself permanent authority.
    #[tokio::test]
    async fn commit_via_public_handler_with_allow_engine_still_requires_attestation() {
        let mut server = test_server();
        let dir = tempfile::tempdir().unwrap();
        server.set_approval_dir_for_test(dir.path().to_path_buf());

        let nonce = insert_rule_proposal_entry(&server, "stellar:testnet", None, DEFAULT_TTL_MS);
        // Calls the PUBLIC handler (`stellar_rule_create_commit`), not
        // `_impl` directly — this is the exact path a real MCP client uses.
        let result = server
            .call_stellar_rule_create_commit(commit_args("stellar:testnet", nonce))
            .await;
        let err = result.expect_err(
            "an Allow-engine profile must still refuse an unattested commit through the public \
             handler",
        );
        assert!(
            err.message.contains("policy.approval_required"),
            "got: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn commit_wrong_kind_entry_is_indistinguishable_approval_required() {
        let mut server = test_server();
        let dir = tempfile::tempdir().unwrap();
        server.set_approval_dir_for_test(dir.path().to_path_buf());

        // Insert a PaymentSimulated entry under the nonce the commit call
        // will present — stellar_rule_create_commit_impl's kind match must
        // refuse it, not treat it as a rule proposal.
        let approvals_dir = server.resolve_approval_dir().unwrap();
        let store_path = approvals_dir.join(format!("{}.toml", server.profile_name_for_approval()));
        let mut store = PendingApprovalStore::open(store_path).unwrap();
        let entry = PendingApproval::new_payment_pending(
            "b64xdr".to_owned(),
            b"fake-xdr",
            TEST_G.to_owned(),
            1_000_000,
            "XLM".to_owned(),
            None,
            100,
            1,
            process_uid_for_attestation().unwrap(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, now_unix_ms().unwrap()).unwrap();
        drop(store);

        let result = server
            .call_stellar_rule_create_commit(commit_args("stellar:testnet", nonce))
            .await;
        let err = result.expect_err("wrong-kind entry must be Err");
        assert!(err.message.contains("policy.approval_required"));
    }

    #[tokio::test]
    async fn commit_chain_id_mismatch_is_simulation_divergence() {
        let mut server = test_server();
        let dir = tempfile::tempdir().unwrap();
        server.set_approval_dir_for_test(dir.path().to_path_buf());

        // The presented chain_id ("stellar:testnet") must itself match the
        // profile to pass dispatch_gate's own chain_id validation; the
        // mismatch under test is against the STORED entry's chain_id
        // ("stellar:mainnet", e.g. a store shared across profiles), not
        // against the profile.
        let nonce = insert_rule_proposal_entry(&server, "stellar:mainnet", None, DEFAULT_TTL_MS);
        let result = server
            .call_stellar_rule_create_commit(commit_args("stellar:testnet", nonce))
            .await;
        let err = result.expect_err("chain_id mismatch must be Err");
        assert!(err.message.contains("simulation.divergence"));
    }

    #[tokio::test]
    async fn commit_digest_mismatch_is_simulation_divergence() {
        let mut server = test_server();
        let dir = tempfile::tempdir().unwrap();
        server.set_approval_dir_for_test(dir.path().to_path_buf());

        // Store an entry whose recorded digest does NOT match what
        // recomputing from its own snapshot would produce.
        let nonce = insert_rule_proposal_entry(
            &server,
            "stellar:testnet",
            Some([0xFFu8; 32]),
            DEFAULT_TTL_MS,
        );
        let result = server
            .call_stellar_rule_create_commit(commit_args("stellar:testnet", nonce))
            .await;
        let err = result.expect_err("digest mismatch must be Err");
        assert!(
            err.message.contains("simulation.divergence"),
            "got: {}",
            err.message
        );
        assert!(err.message.contains("recomputed digest"));
    }

    #[tokio::test]
    async fn commit_missing_attestation_when_required_is_indistinguishable_approval_required() {
        let mut server = test_server();
        let dir = tempfile::tempdir().unwrap();
        server.set_approval_dir_for_test(dir.path().to_path_buf());

        let nonce = insert_rule_proposal_entry(&server, "stellar:testnet", None, DEFAULT_TTL_MS);
        let forced = DispatchOutcome::RequireApproval(
            stellar_agent_core::policy::ApprovalRequest::new(nonce.clone(), 86_400),
        );
        let result = server
            .stellar_rule_create_commit_impl(commit_args("stellar:testnet", nonce), Some(forced))
            .await;
        let err = result.expect_err("missing attestation under RequireApproval must be Err");
        assert!(err.message.contains("policy.approval_required"));
    }

    #[tokio::test]
    async fn commit_malformed_attestation_base64_is_indistinguishable_approval_required() {
        let mut server = test_server();
        let dir = tempfile::tempdir().unwrap();
        server.set_approval_dir_for_test(dir.path().to_path_buf());

        let nonce = insert_rule_proposal_entry(&server, "stellar:testnet", None, DEFAULT_TTL_MS);
        let mut args = commit_args("stellar:testnet", nonce.clone());
        args.approval_attestation = Some("not valid base64!!".to_owned());
        let forced = DispatchOutcome::RequireApproval(
            stellar_agent_core::policy::ApprovalRequest::new(nonce, 86_400),
        );
        let result = server
            .stellar_rule_create_commit_impl(args, Some(forced))
            .await;
        let err = result.expect_err("malformed attestation base64 must be Err");
        assert!(err.message.contains("policy.approval_required"));
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn commit_wrong_attestation_is_indistinguishable_approval_required() {
        stellar_agent_test_support::keyring_mock::install().ok();

        let mut server = test_server();
        let dir = tempfile::tempdir().unwrap();
        server.set_approval_dir_for_test(dir.path().to_path_buf());

        let nonce = insert_rule_proposal_entry(&server, "stellar:testnet", None, DEFAULT_TTL_MS);
        let mut args = commit_args("stellar:testnet", nonce.clone());
        // Syntactically valid but wrong 32-byte HMAC — the attestation key
        // is never seeded in the keyring for this profile, so this will
        // fail at key-load (not the HMAC compare itself), but must still
        // collapse to the same indistinguishable wire code.
        args.approval_attestation =
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32]));
        let forced = DispatchOutcome::RequireApproval(
            stellar_agent_core::policy::ApprovalRequest::new(nonce, 86_400),
        );
        let result = server
            .stellar_rule_create_commit_impl(args, Some(forced))
            .await;
        let err = result.expect_err("wrong attestation must be Err");
        assert!(err.message.contains("policy.approval_required"));
    }

    // ── Mainnet write defence ─────────────────────────────────────────────────

    #[tokio::test]
    async fn propose_refuses_mainnet_chain_id() {
        let server = test_server();
        let json = serde_json::json!({
            "chain_id": "stellar:mainnet",
            "smart_account": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "name": "spend-daily",
            "signers": [
                {"kind": "delegated", "address": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
            ],
        });
        let args: StellarRuleCreateArgs = serde_json::from_value(json).expect("deserialise");
        let result = server.call_stellar_rule_create(args).await;
        let err = result.expect_err("mainnet must be refused before any RPC call");
        assert!(
            err.message.contains("network.mainnet_write_forbidden"),
            "got: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn commit_refuses_mainnet_chain_id() {
        let server = test_server();
        // The mainnet refusal fires before any nonce lookup, so an
        // arbitrary/never-inserted nonce is sufficient for this test.
        let result = server
            .call_stellar_rule_create_commit(commit_args("stellar:mainnet", "any-nonce".to_owned()))
            .await;
        let err = result.expect_err("mainnet must be refused before any nonce lookup");
        assert!(
            err.message.contains("network.mainnet_write_forbidden"),
            "got: {}",
            err.message
        );
    }
}
