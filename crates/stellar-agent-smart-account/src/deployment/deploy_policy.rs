//! Unified `smart-account deploy-policy --kind <...>` deploy substrate.
//!
//! One verb, three policy kinds:
//!
//! - `simple-threshold` — deploys the vendored OZ
//!   `multisig-threshold-policy-example` WASM (already embedded at
//!   [`crate::signers::policy_identification::THRESHOLD_POLICY_WASM`]); the
//!   FIRST deploy CLI for this policy.
//! - `spending-limit` — routes to the existing, sealed
//!   [`mod@crate::deployment::deploy_spending_limit_policy`] substrate
//!   verbatim. `smart-account deploy-spending-limit-policy` remains as its
//!   own verb; this is an additive front door, not a replacement.
//! - `weighted-threshold` — deploys the vendored OZ
//!   `multisig-weighted-threshold-policy-example` WASM
//!   ([`crate::weighted_threshold_policy::WEIGHTED_THRESHOLD_POLICY_WASM`]).
//!
//! All three kinds share the same per-network-singleton deploy flow: runtime
//! SHA gate, idempotency check against the [`VerifierRegistry`],
//! `UploadContractWasm` (conditional) + `CreateContractV2` (no
//! `__constructor` args — none of the three policy contracts has one),
//! post-deploy wasm-hash verification, and registry recording. This mirrors
//! `deploy_spending_limit_policy.rs`'s deploy flow exactly; see that module's
//! rustdoc for the step-by-step narrative.
//!
//! # Deterministic salt
//!
//! Each kind uses its OWN salt domain prefix, so the three kinds derive
//! different contract addresses on the same network even for the same
//! deployer:
//! - simple-threshold: `"oz-simple-threshold-policy-v0.7.2-"`
//! - weighted-threshold: `"oz-weighted-threshold-policy-v0.7.2-"`
//! - spending-limit: `"oz-spending-limit-policy-v0.7.2-"` (unchanged; defined
//!   in `deploy_spending_limit_policy.rs`).

use std::time::Duration;

use sha2::{Digest as _, Sha256};
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::SaInvocationResult;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::error::{SubmissionError, WalletError};
use stellar_agent_core::rpc_budget::{SequentialRpcBudget, bound_stage};
use stellar_agent_network::{
    StellarRpcClient, fetch_account, signing::envelope_signing::attach_signature,
    submit_transaction_and_wait,
};
use stellar_baselib::account::{Account as BaselibAccount, AccountBehavior};
use stellar_baselib::transaction::{Transaction, TransactionBehavior};
use stellar_baselib::transaction_builder::{TransactionBuilder, TransactionBuilderBehavior};
use stellar_rpc_client::Client;
use stellar_strkey::Contract as ContractStrkey;
use stellar_xdr::{
    AccountId, BytesM, ContractDataDurability, ContractExecutable, ContractId, ContractIdPreimage,
    ContractIdPreimageFromAddress, CreateContractArgsV2, Hash, HostFunction, InvokeHostFunctionOp,
    LedgerKey, LedgerKeyContractCode, LedgerKeyContractData, Limits, Operation, OperationBody,
    PublicKey as XdrPublicKey, ScAddress, ScVal, SorobanAuthorizationEntry, Uint256, VecM,
    WriteXdr,
};
use tracing::info;

use crate::SaError;
use crate::deployment::address::derive_smart_account_address;
use crate::deployment::deploy::{
    DeployerKeypair, ResolvedFeePerOp, caip2_chain_id_for_passphrase, decode_hex32,
    redact_wasm_hash, to_hex, uuid_v4_hex, verify_post_deploy_wasm_hash,
};
use crate::deployment::deploy_spending_limit_policy::{
    SpendingLimitPolicyDeployArgs, deploy_spending_limit_policy,
};
use crate::deployment::map_budget_elapsed;
use crate::signers::policy_identification::{THRESHOLD_POLICY_WASM, THRESHOLD_POLICY_WASM_HASHES};
use crate::verifiers::{RecordOutcome, VerifierRegistry};
use crate::weighted_threshold_policy::{
    WEIGHTED_THRESHOLD_POLICY_WASM, WEIGHTED_THRESHOLD_POLICY_WASM_SHA256,
};

/// Salt-domain prefix for the simple-threshold-policy deploy.
///
/// Mirrors `POLICY_SALT_DOMAIN_PREFIX` in `deploy_spending_limit_policy.rs`:
/// the version suffix pins the salt to the OZ WASM version, so a future
/// policy bump produces a different address even on the same network with
/// the same deployer.
const SIMPLE_THRESHOLD_SALT_DOMAIN_PREFIX: &str = "oz-simple-threshold-policy-v0.7.2-";

/// Salt-domain prefix for the weighted-threshold-policy deploy.
const WEIGHTED_THRESHOLD_SALT_DOMAIN_PREFIX: &str = "oz-weighted-threshold-policy-v0.7.2-";

// ── Public types ──────────────────────────────────────────────────────────────

/// Selects which policy contract `deploy_policy` deploys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyDeployKind {
    /// OZ `multisig-threshold-policy-example` (unweighted signer-count threshold).
    SimpleThreshold,
    /// OZ `multisig-spending-limit-policy-example` (routes to the existing,
    /// sealed `deploy_spending_limit_policy` substrate).
    SpendingLimit,
    /// OZ `multisig-weighted-threshold-policy-example` (weighted-signer quorum).
    WeightedThreshold,
}

impl PolicyDeployKind {
    /// Returns the CLI-facing kebab-case label (`--kind` value) for this kind.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::SimpleThreshold => "simple-threshold",
            Self::SpendingLimit => "spending-limit",
            Self::WeightedThreshold => "weighted-threshold",
        }
    }
}

/// Arguments for [`deploy_policy`].
pub struct PolicyDeployArgs {
    /// Which policy contract to deploy.
    pub kind: PolicyDeployKind,
    /// Deployer keypair (same three-mode shape as `DeploymentArgs::deployer`).
    pub deployer: DeployerKeypair,
    /// Stellar network passphrase.
    pub network_passphrase: String,
    /// Soroban RPC endpoint URL.
    pub rpc_url: String,
    /// Polling timeout for `submit_transaction_and_wait`.
    pub timeout: Duration,
    /// Pre-resolved base fee per operation in stroops.
    pub fee: ResolvedFeePerOp,
    /// If `true`, compute and return the derived contract address without any network access.
    pub dry_run: bool,
    /// Path override for the [`VerifierRegistry`] (uses default OS path when `None`).
    pub registry_path_override: Option<std::path::PathBuf>,
}

/// Result of a successful [`deploy_policy`] call.
#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
pub struct PolicyDeployResult {
    /// Which policy contract was (or would be) deployed.
    pub kind: &'static str,
    /// Deployed (or existing) policy contract C-strkey.
    pub policy_address: String,
    /// SHA-256 of the deployed WASM, 64-char lowercase hex.
    pub policy_wasm_sha256: String,
    /// Stellar network passphrase for which the policy was deployed.
    pub network_passphrase: String,
    /// Transaction hash of the `CreateContractV2` deploy transaction.
    ///
    /// `None` when `already_deployed` or `dry_run`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    /// Confirmed ledger sequence. `None` when `already_deployed` or `dry_run`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ledger: Option<u32>,
    /// Outcome label: `"deployed"`, `"already_deployed"`, or `"dry_run"`.
    pub status: &'static str,
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Deploys the policy contract selected by `args.kind` and records the
/// address in the wallet-local [`VerifierRegistry`].
///
/// `--kind spending-limit` delegates directly to the existing
/// [`deploy_spending_limit_policy`] substrate (including its own audit-log
/// emission); the other two kinds share the generic per-network-singleton
/// deploy flow implemented in this module and emit their own
/// `SaRawInvocation` audit row here.
///
/// # Errors
///
/// - [`SaError::SimpleThresholdPolicyProvenanceMismatch`] /
///   [`SaError::WeightedThresholdPolicyProvenanceMismatch`] — runtime SHA
///   gate failed.
/// - [`SaError::SimpleThresholdPolicySha256Drift`] /
///   [`SaError::WeightedThresholdPolicySha256Drift`] — registry has a
///   different sha256 for network.
/// - [`SaError::SpendingLimitPolicyProvenanceMismatch`] /
///   [`SaError::SpendingLimitPolicySha256Drift`] — for `--kind spending-limit`.
/// - [`SaError::NetworksTomlIo`] / [`SaError::NetworksTomlParse`] — registry
///   read/write failed.
/// - [`SaError::DeploymentFailed`] — Soroban deployment failed at one of the
///   canonical phases.
///
/// # Panics
///
/// Never panics in release mode.
pub async fn deploy_policy(
    args: PolicyDeployArgs,
    audit_writer: Option<&mut AuditWriter>,
) -> Result<PolicyDeployResult, SaError> {
    match args.kind {
        PolicyDeployKind::SpendingLimit => {
            let inner = SpendingLimitPolicyDeployArgs {
                deployer: args.deployer,
                network_passphrase: args.network_passphrase,
                rpc_url: args.rpc_url,
                timeout: args.timeout,
                fee: args.fee,
                dry_run: args.dry_run,
                registry_path_override: args.registry_path_override,
            };
            let result = deploy_spending_limit_policy(inner, audit_writer).await?;
            Ok(PolicyDeployResult {
                kind: PolicyDeployKind::SpendingLimit.label(),
                policy_address: result.policy_address,
                policy_wasm_sha256: result.policy_wasm_sha256,
                network_passphrase: result.network_passphrase,
                tx_hash: result.tx_hash,
                ledger: result.ledger,
                status: result.status,
            })
        }
        PolicyDeployKind::SimpleThreshold => {
            let wasm_sha256 = to_hex(&THRESHOLD_POLICY_WASM_HASHES[0]);
            deploy_wasm_policy(
                PolicyWasmSpec {
                    kind: PolicyDeployKind::SimpleThreshold,
                    wasm: THRESHOLD_POLICY_WASM,
                    wasm_sha256,
                    salt_domain_prefix: SIMPLE_THRESHOLD_SALT_DOMAIN_PREFIX,
                    provenance_mismatch: |expected, actual| {
                        SaError::SimpleThresholdPolicyProvenanceMismatch { expected, actual }
                    },
                    existing_entry: |reg, net| {
                        reg.simple_threshold_policy_for(net)
                            .map(|e| (e.address.clone(), e.wasm_sha256.clone()))
                    },
                    record: |reg, net, addr, sha| {
                        reg.record_simple_threshold_policy(net, addr, sha)
                    },
                },
                args,
                audit_writer,
            )
            .await
        }
        PolicyDeployKind::WeightedThreshold => {
            deploy_wasm_policy(
                PolicyWasmSpec {
                    kind: PolicyDeployKind::WeightedThreshold,
                    wasm: WEIGHTED_THRESHOLD_POLICY_WASM,
                    wasm_sha256: WEIGHTED_THRESHOLD_POLICY_WASM_SHA256.to_owned(),
                    salt_domain_prefix: WEIGHTED_THRESHOLD_SALT_DOMAIN_PREFIX,
                    provenance_mismatch: |expected, actual| {
                        SaError::WeightedThresholdPolicyProvenanceMismatch { expected, actual }
                    },
                    existing_entry: |reg, net| {
                        reg.weighted_threshold_policy_for(net)
                            .map(|e| (e.address.clone(), e.wasm_sha256.clone()))
                    },
                    record: |reg, net, addr, sha| {
                        reg.record_weighted_threshold_policy(net, addr, sha)
                    },
                },
                args,
                audit_writer,
            )
            .await
        }
    }
}

// ── Generic WASM-policy deploy substrate ─────────────────────────────────────

/// Per-kind configuration for [`deploy_wasm_policy`].
///
/// Function-pointer fields (non-capturing closures coerce to `fn` types)
/// parameterise the registry idempotency check, the registry record call,
/// and the provenance-mismatch error constructor — the only three points
/// where `simple-threshold` and `weighted-threshold` differ beyond their WASM
/// bytes and salt domain.
struct PolicyWasmSpec {
    kind: PolicyDeployKind,
    wasm: &'static [u8],
    wasm_sha256: String,
    salt_domain_prefix: &'static str,
    provenance_mismatch: fn(expected: String, actual: String) -> SaError,
    /// Returns the registry's recorded `(address, wasm_sha256)` for this
    /// kind, if any. The address is the ACTUAL deployed contract address —
    /// distinct from any address freshly re-derived from the CURRENT call's
    /// deployer, which would be wrong if a different deployer re-runs
    /// `deploy_policy` against the same registry (the salt derivation is
    /// deployer-keyed; the registry's idempotency check is sha256-keyed
    /// only).
    existing_entry: fn(&VerifierRegistry, &str) -> Option<(String, String)>,
    record: fn(&mut VerifierRegistry, &str, String, String) -> Result<RecordOutcome, SaError>,
}

async fn deploy_wasm_policy(
    spec: PolicyWasmSpec,
    args: PolicyDeployArgs,
    audit_writer: Option<&mut AuditWriter>,
) -> Result<PolicyDeployResult, SaError> {
    let chain_id = caip2_chain_id_for_passphrase(&args.network_passphrase);
    let is_dry_run = args.dry_run;

    let outcome = deploy_wasm_policy_body(&spec, args).await;

    if let Some(writer) = audit_writer {
        if is_dry_run {
            return outcome;
        }

        let request_id = uuid_v4_hex();
        let sa_result = match &outcome {
            Ok(_) => SaInvocationResult::Success,
            Err(SaError::DeploymentFailed {
                phase: "upload" | "deploy" | "submit" | "post_deploy_verification",
                ..
            }) => SaInvocationResult::OnChainRejected,
            Err(_) => SaInvocationResult::PreSubmissionRefused,
        };

        let (wire_code, contract_for_audit) = match &outcome {
            Ok(result) => (
                "sa.ok",
                stellar_agent_core::observability::redact_strkey_first5_last5(
                    &result.policy_address,
                ),
            ),
            Err(e) => (e.wire_code(), "unknown".to_owned()),
        };

        let ra_entry = AuditEntry::new_sa_raw_invocation(
            contract_for_audit,
            wire_code,
            None,
            0,
            sa_result,
            &chain_id,
            &request_id,
        );
        if let Err(e) = writer.write_entry(ra_entry) {
            tracing::warn!(
                error = %e,
                kind = spec.kind.label(),
                "deploy_policy: SaRawInvocation audit write failed"
            );
        }
    }

    outcome
}

async fn deploy_wasm_policy_body(
    spec: &PolicyWasmSpec,
    args: PolicyDeployArgs,
) -> Result<PolicyDeployResult, SaError> {
    // ── Step 1: Runtime SHA gate ──────────────────────────────────────────────
    {
        let mut h = Sha256::new();
        h.update(spec.wasm);
        let actual = to_hex(&h.finalize());
        if actual != spec.wasm_sha256 {
            return Err((spec.provenance_mismatch)(spec.wasm_sha256.clone(), actual));
        }
    }

    let wasm_hash_bytes: [u8; 32] =
        decode_hex32(&spec.wasm_sha256).map_err(|()| SaError::DeploymentFailed {
            phase: "build",
            redacted_reason: format!(
                "{} wasm sha256 const is not valid 64-char hex",
                spec.kind.label()
            ),
        })?;

    // ── Step 2: Resolve deployer G-strkey ─────────────────────────────────────
    let deployer_pubkey =
        args.deployer
            .deployer_pubkey()
            .await
            .map_err(|e| SaError::DeploymentFailed {
                phase: "build",
                redacted_reason: format!("failed to obtain deployer pubkey: {e}"),
            })?;

    // ── Step 3: Compute deterministic salt ────────────────────────────────────
    let salt_input = format!("{}{}", spec.salt_domain_prefix, args.network_passphrase);
    let salt: [u8; 32] = Sha256::digest(salt_input.as_bytes()).into();
    let salt_hex = to_hex(&salt);

    // ── Step 4: Derive the expected policy C-strkey (pure, no network) ────────
    let derived_policy_address =
        derive_smart_account_address(&deployer_pubkey, &salt, &args.network_passphrase).map_err(
            |e| SaError::DeploymentFailed {
                phase: "build",
                redacted_reason: format!("policy address derivation failed: {e}"),
            },
        )?;

    // ── Dry-run path ──────────────────────────────────────────────────────────
    if args.dry_run {
        return Ok(PolicyDeployResult {
            kind: spec.kind.label(),
            policy_address: derived_policy_address,
            policy_wasm_sha256: spec.wasm_sha256.clone(),
            network_passphrase: args.network_passphrase,
            tx_hash: None,
            ledger: None,
            status: "dry_run",
        });
    }

    // ── Step 5: Idempotency check via VerifierRegistry ────────────────────────
    let mut registry = match args.registry_path_override {
        Some(ref p) => VerifierRegistry::open_at(p.clone()),
        None => VerifierRegistry::open(),
    }?;

    if let Some((existing_address, existing_sha256)) =
        (spec.existing_entry)(&registry, &args.network_passphrase)
    {
        if existing_sha256 == spec.wasm_sha256 {
            info!(
                kind = spec.kind.label(),
                network = &args.network_passphrase,
                "deploy_policy: already deployed; returning existing entry"
            );
            // Return the REGISTRY's recorded address, not a freshly-derived
            // one: the salt derivation is keyed on the CURRENT call's
            // deployer, so a different deployer re-running `deploy_policy`
            // against the same registry would otherwise get back an address
            // that was never actually deployed (the real contract was
            // created by whichever deployer ran it first).
            return Ok(PolicyDeployResult {
                kind: spec.kind.label(),
                policy_address: existing_address,
                policy_wasm_sha256: existing_sha256,
                network_passphrase: args.network_passphrase,
                tx_hash: None,
                ledger: None,
                status: "already_deployed",
            });
        }
        return Err(match spec.kind {
            PolicyDeployKind::SimpleThreshold => SaError::SimpleThresholdPolicySha256Drift {
                network: args.network_passphrase,
                recorded: existing_sha256,
                attempted: spec.wasm_sha256.clone(),
            },
            PolicyDeployKind::WeightedThreshold => SaError::WeightedThresholdPolicySha256Drift {
                network: args.network_passphrase,
                recorded: existing_sha256,
                attempted: spec.wasm_sha256.clone(),
            },
            PolicyDeployKind::SpendingLimit => unreachable!(
                "deploy_wasm_policy is never invoked with PolicyDeployKind::SpendingLimit"
            ),
        });
    }

    // ── Step 6: Construct RPC clients ────────────────────────────────────────
    let rpc_server = Client::new(&args.rpc_url).map_err(|e| SaError::DeploymentFailed {
        phase: "build",
        redacted_reason: format!("rpc-server construction failed: {e}"),
    })?;

    let network_client =
        StellarRpcClient::new(&args.rpc_url).map_err(|e| SaError::DeploymentFailed {
            phase: "build",
            redacted_reason: format!("StellarRpcClient construction failed: {e}"),
        })?;

    // ── Step 7: Fetch deployer account sequence ───────────────────────────────
    // One collective wall-clock budget for every RPC stage below.
    // Each stage is individually bounded at 60s by the transport; without
    // a shared deadline the flow's total wall time is the SUM of every
    // stage's transport bound plus the submit-and-wait poll(s), which can
    // exceed `args.timeout` by several multiples. Reusing `args.timeout` —
    // the caller's existing polling budget — as the ONE total makes the
    // whole flow's wall-clock ceiling match what the caller already
    // configured, rather than each stage re-arming its own allowance.
    let deploy_budget = SequentialRpcBudget::new(args.timeout);

    let deployer_view = bound_stage(
        deploy_budget,
        "fetch_deployer_account",
        fetch_account(&network_client, &deployer_pubkey, &[]),
    )
    .await
    .map_err(|elapsed| map_budget_elapsed(elapsed, "build"))?
    .map_err(|e| SaError::DeploymentFailed {
        phase: "build",
        redacted_reason: format!("deployer account fetch failed: {e}"),
    })?;

    let mut deployer_account =
        BaselibAccount::new(&deployer_pubkey, &deployer_view.sequence_number.to_string()).map_err(
            |e| SaError::DeploymentFailed {
                phase: "build",
                redacted_reason: format!("BaselibAccount::new failed: {e:?}"),
            },
        )?;

    let base_fee = args.fee.stroops;

    // ── Step 8: Upload WASM (conditional — skip if already on-chain) ──────────
    let wasm_key = LedgerKey::ContractCode(LedgerKeyContractCode {
        hash: Hash(wasm_hash_bytes),
    });

    let wasm_query_resp = bound_stage(
        deploy_budget,
        "wasm_preflight_get_ledger_entries",
        rpc_server.get_ledger_entries(&[wasm_key]),
    )
    .await
    .map_err(|elapsed| map_budget_elapsed(elapsed, "build"))?
    .map_err(|e| SaError::DeploymentFailed {
        phase: "build",
        redacted_reason: format!("getLedgerEntries (wasm pre-flight) failed: {e}"),
    })?;

    let wasm_already_on_chain = match wasm_query_resp.entries.as_ref() {
        Some(entries) => !entries.is_empty(),
        None => false,
    };

    let upload_tx_hash: Option<String> = if wasm_already_on_chain {
        info!(
            kind = spec.kind.label(),
            wasm_hash = %redact_wasm_hash(&spec.wasm_sha256),
            "deploy_policy: WASM already on-chain; skipping upload"
        );
        None
    } else {
        info!(
            kind = spec.kind.label(),
            wasm_hash = %redact_wasm_hash(&spec.wasm_sha256),
            "deploy_policy: uploading WASM"
        );

        let wasm_bytes: BytesM =
            spec.wasm
                .to_vec()
                .try_into()
                .map_err(|_| SaError::DeploymentFailed {
                    phase: "build",
                    redacted_reason: "WASM exceeds BytesM maximum length".to_owned(),
                })?;

        let upload_op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::UploadContractWasm(wasm_bytes),
                auth: VecM::default(),
            }),
        };

        let mut upload_tx_builder =
            TransactionBuilder::new(&mut deployer_account, &args.network_passphrase, None);
        upload_tx_builder.fee(base_fee);
        upload_tx_builder.add_operation(upload_op);
        let upload_tx: Transaction = upload_tx_builder.build_for_simulation();

        let upload_envelope = upload_tx
            .to_envelope()
            .map_err(|e| SaError::DeploymentFailed {
                phase: "build",
                redacted_reason: format!("upload to_envelope (pre-sim) failed: {e}"),
            })?;
        let upload_sim = bound_stage(
            deploy_budget,
            "upload_simulate",
            rpc_server.simulate_transaction_envelope(&upload_envelope, None),
        )
        .await
        .map_err(|elapsed| map_budget_elapsed(elapsed, "simulate"))?
        .map_err(|e| SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: format!("upload simulate_transaction_envelope failed: {e}"),
        })?;

        if let Some(sim_error) = &upload_sim.error {
            return Err(SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!("upload simulation returned error: {sim_error}"),
            });
        }
        if upload_sim.min_resource_fee == 0 || upload_sim.transaction_data.is_empty() {
            return Err(SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: "upload rpc returned response without simulation result"
                    .to_owned(),
            });
        }

        let upload_resource_fee =
            u32::try_from(upload_sim.min_resource_fee).map_err(|e| SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!("upload min_resource_fee cast failed: {e}"),
            })?;
        let mut prepared_upload = upload_tx.clone();
        prepared_upload.fee = prepared_upload.fee.saturating_add(upload_resource_fee);
        prepared_upload.soroban_data =
            Some(
                upload_sim
                    .transaction_data()
                    .map_err(|e| SaError::DeploymentFailed {
                        phase: "simulate",
                        redacted_reason: format!("upload transaction_data decode failed: {e}"),
                    })?,
            );

        let signed_upload_xdr = attach_signature(
            &prepared_upload
                .to_envelope()
                .map_err(|e| SaError::DeploymentFailed {
                    phase: "build",
                    redacted_reason: format!("upload to_envelope failed: {e}"),
                })?
                .to_xdr_base64(Limits::none())
                .map_err(|e| SaError::DeploymentFailed {
                    phase: "build",
                    redacted_reason: format!("upload XDR encode failed: {e}"),
                })?,
            args.deployer.signer(),
            &args.network_passphrase,
        )
        .await
        .map_err(|e| SaError::DeploymentFailed {
            phase: "build",
            redacted_reason: format!("upload signing failed: {e}"),
        })?;

        let upload_submission = bound_stage(
            deploy_budget,
            "upload_submit_and_wait",
            submit_transaction_and_wait(
                &network_client,
                &signed_upload_xdr,
                args.timeout,
                &args.network_passphrase,
                None,
            ),
        )
        .await
        .map_err(|elapsed| map_budget_elapsed(elapsed, "upload"))?
        .map_err(|e| {
            let reason = e.to_string();
            let phase = match &e {
                WalletError::Submission(
                    SubmissionError::TxMalformed { .. } | SubmissionError::SequenceNumberStale,
                ) => "submit",
                _ => "upload",
            };
            SaError::DeploymentFailed {
                phase,
                redacted_reason: format!("upload submission failed: {reason}"),
            }
        })?;

        info!(
            kind = spec.kind.label(),
            upload_tx_hash = %stellar_agent_network::redact_tx_hash(&upload_submission.tx_hash),
            ledger = upload_submission.ledger,
            "deploy_policy: WASM uploaded"
        );

        let deployer_view2 = bound_stage(
            deploy_budget,
            "fetch_deployer_account_post_upload",
            fetch_account(&network_client, &deployer_pubkey, &[]),
        )
        .await
        .map_err(|elapsed| map_budget_elapsed(elapsed, "build"))?
        .map_err(|e| SaError::DeploymentFailed {
            phase: "build",
            redacted_reason: format!("deployer account re-fetch after upload failed: {e}"),
        })?;
        deployer_account = BaselibAccount::new(
            &deployer_pubkey,
            &deployer_view2.sequence_number.to_string(),
        )
        .map_err(|e| SaError::DeploymentFailed {
            phase: "build",
            redacted_reason: format!("BaselibAccount::new (post-upload) failed: {e:?}"),
        })?;

        Some(upload_submission.tx_hash)
    };

    // ── Step 9: Build the CreateContractV2 deploy transaction ─────────────────
    //
    // None of the three vendored policy contracts has a `__constructor`; each
    // exports only its `Policy` trait methods plus (for weighted-threshold)
    // the query/mutator surface. Constructor args are always empty.
    let deployer_pk =
        stellar_strkey::ed25519::PublicKey::from_string(&deployer_pubkey).map_err(|_| {
            SaError::DeploymentFailed {
                phase: "build",
                redacted_reason: "deployer G-strkey parse failed after fetch_account succeeded"
                    .to_owned(),
            }
        })?;

    let deployer_sc_address = ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
        Uint256(deployer_pk.0),
    )));

    let constructor_args: VecM<ScVal> = VecM::default();

    let create_contract_fn = HostFunction::CreateContractV2(CreateContractArgsV2 {
        contract_id_preimage: ContractIdPreimage::Address(ContractIdPreimageFromAddress {
            address: deployer_sc_address,
            salt: Uint256(salt),
        }),
        executable: ContractExecutable::Wasm(Hash(wasm_hash_bytes)),
        constructor_args,
    });

    let create_op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: create_contract_fn,
            auth: VecM::default(),
        }),
    };

    let mut tx_builder =
        TransactionBuilder::new(&mut deployer_account, &args.network_passphrase, None);
    tx_builder.fee(base_fee);
    tx_builder.add_operation(create_op);
    let tx: Transaction = tx_builder.build_for_simulation();

    // ── Step 10: Simulate + prepare ───────────────────────────────────────────
    let deploy_envelope_pre = tx.to_envelope().map_err(|e| SaError::DeploymentFailed {
        phase: "build",
        redacted_reason: format!("deploy to_envelope (pre-sim) failed: {e}"),
    })?;
    let sim_response = bound_stage(
        deploy_budget,
        "deploy_simulate",
        rpc_server.simulate_transaction_envelope(&deploy_envelope_pre, None),
    )
    .await
    .map_err(|elapsed| map_budget_elapsed(elapsed, "simulate"))?
    .map_err(|e| SaError::DeploymentFailed {
        phase: "simulate",
        redacted_reason: format!("deploy simulate_transaction_envelope failed: {e}"),
    })?;

    if let Some(sim_error) = &sim_response.error {
        return Err(SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: format!("deploy simulation returned error: {sim_error}"),
        });
    }
    if sim_response.min_resource_fee == 0 || sim_response.transaction_data.is_empty() {
        return Err(SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: "deploy rpc returned response without simulation result".to_owned(),
        });
    }

    let deploy_resource_fee =
        u32::try_from(sim_response.min_resource_fee).map_err(|e| SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: format!("deploy min_resource_fee cast failed: {e}"),
        })?;
    let deploy_sim_auth: VecM<SorobanAuthorizationEntry> = sim_response
        .results()
        .ok()
        .and_then(|rs| rs.into_iter().next())
        .map(|r| r.auth)
        .unwrap_or_default()
        .try_into()
        .map_err(|e| SaError::DeploymentFailed {
            phase: "build",
            redacted_reason: format!("deploy auth VecM encode failed: {e:?}"),
        })?;
    let mut prepared_tx = tx.clone();
    prepared_tx.fee = prepared_tx.fee.saturating_add(deploy_resource_fee);
    prepared_tx.soroban_data =
        Some(
            sim_response
                .transaction_data()
                .map_err(|e| SaError::DeploymentFailed {
                    phase: "simulate",
                    redacted_reason: format!("deploy transaction_data decode failed: {e}"),
                })?,
        );
    if let Some(op) = prepared_tx
        .operations
        .as_mut()
        .and_then(|ops| ops.get_mut(0))
        && let OperationBody::InvokeHostFunction(ihf) = &mut op.body
    {
        ihf.auth = deploy_sim_auth;
    }

    // ── Step 11: Sign + submit ────────────────────────────────────────────────
    let signed_xdr = attach_signature(
        &prepared_tx
            .to_envelope()
            .map_err(|e| SaError::DeploymentFailed {
                phase: "build",
                redacted_reason: format!("deploy to_envelope failed: {e}"),
            })?
            .to_xdr_base64(Limits::none())
            .map_err(|e| SaError::DeploymentFailed {
                phase: "build",
                redacted_reason: format!("deploy XDR encode failed: {e}"),
            })?,
        args.deployer.signer(),
        &args.network_passphrase,
    )
    .await
    .map_err(|e| SaError::DeploymentFailed {
        phase: "build",
        redacted_reason: format!("deploy signing failed: {e}"),
    })?;

    info!(
        kind = spec.kind.label(),
        deployer = %stellar_agent_core::observability::redact_strkey_first5_last5(&deployer_pubkey),
        salt = %stellar_agent_core::hex::redact_hex_first8_last8(&salt_hex),
        wasm_hash = %redact_wasm_hash(&spec.wasm_sha256),
        "deploy_policy: submitting deploy transaction"
    );

    let submission = bound_stage(
        deploy_budget,
        "deploy_submit_and_wait",
        submit_transaction_and_wait(
            &network_client,
            &signed_xdr,
            args.timeout,
            &args.network_passphrase,
            None,
        ),
    )
    .await
    .map_err(|elapsed| map_budget_elapsed(elapsed, "deploy"))?
    .map_err(|e| {
        let reason = e.to_string();
        let phase = match &e {
            WalletError::Submission(SubmissionError::TxMalformed { .. }) => "submit",
            _ => "deploy",
        };
        SaError::DeploymentFailed {
            phase,
            redacted_reason: format!("deploy submission failed: {reason}"),
        }
    })?;

    // ── Step 12: Post-deploy WASM-hash verification ───────────────────────────
    let c_strkey_decoded = ContractStrkey::from_string(&derived_policy_address).map_err(|e| {
        SaError::DeploymentFailed {
            phase: "post_deploy_verification",
            redacted_reason: format!("c-strkey decode failed: {e}"),
        }
    })?;

    let contract_sc_address = ScAddress::Contract(ContractId(Hash(c_strkey_decoded.0)));
    let instance_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: contract_sc_address,
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });

    let post_deploy_resp = bound_stage(
        deploy_budget,
        "post_deploy_get_ledger_entries",
        rpc_server.get_ledger_entries(&[instance_key]),
    )
    .await
    .map_err(|elapsed| map_budget_elapsed(elapsed, "post_deploy_verification"))?
    .map_err(|e| SaError::DeploymentFailed {
        phase: "post_deploy_verification",
        redacted_reason: format!("getLedgerEntries (post-deploy verify) failed: {e}"),
    })?;

    let entries = post_deploy_resp.entries.unwrap_or_default();
    let entry = entries.first().ok_or_else(|| SaError::DeploymentFailed {
        phase: "post_deploy_verification",
        redacted_reason: "post-deploy getLedgerEntries returned no entries".to_owned(),
    })?;

    verify_post_deploy_wasm_hash(entry, &spec.wasm_sha256, &derived_policy_address)?;

    info!(
        kind = spec.kind.label(),
        policy = %stellar_agent_core::observability::redact_strkey_first5_last5(
            &derived_policy_address),
        tx_hash = %stellar_agent_network::redact_tx_hash(&submission.tx_hash),
        ledger = submission.ledger,
        "deploy_policy: deployment verified"
    );

    // ── Step 13: Record in registry ───────────────────────────────────────────
    let _ = (spec.record)(
        &mut registry,
        &args.network_passphrase,
        derived_policy_address.clone(),
        spec.wasm_sha256.clone(),
    )?;
    registry.persist()?;

    let _ = upload_tx_hash;

    Ok(PolicyDeployResult {
        kind: spec.kind.label(),
        policy_address: derived_policy_address,
        policy_wasm_sha256: spec.wasm_sha256.clone(),
        network_passphrase: args.network_passphrase,
        tx_hash: Some(submission.tx_hash),
        ledger: Some(submission.ledger),
        status: "deployed",
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    #![allow(clippy::expect_used, reason = "test-only")]

    use super::*;

    /// `PolicyDeployKind::label()` returns the exact `--kind` CLI value for
    /// each variant.
    #[test]
    fn kind_label_matches_cli_grammar() {
        assert_eq!(
            PolicyDeployKind::SimpleThreshold.label(),
            "simple-threshold"
        );
        assert_eq!(PolicyDeployKind::SpendingLimit.label(), "spending-limit");
        assert_eq!(
            PolicyDeployKind::WeightedThreshold.label(),
            "weighted-threshold"
        );
    }

    /// The simple-threshold and weighted-threshold salt domains differ from
    /// each other and from the spending-limit domain (defined in the sibling
    /// module), so the three kinds derive distinct addresses for the same
    /// deployer + network.
    #[test]
    fn salt_domains_are_distinct() {
        let passphrase = "Test SDF Network ; September 2015";
        let simple = format!("{SIMPLE_THRESHOLD_SALT_DOMAIN_PREFIX}{passphrase}");
        let weighted = format!("{WEIGHTED_THRESHOLD_SALT_DOMAIN_PREFIX}{passphrase}");
        let spending_limit = format!("oz-spending-limit-policy-v0.7.2-{passphrase}");

        assert_ne!(simple, weighted);
        assert_ne!(simple, spending_limit);
        assert_ne!(weighted, spending_limit);

        let simple_salt: [u8; 32] = Sha256::digest(simple.as_bytes()).into();
        let weighted_salt: [u8; 32] = Sha256::digest(weighted.as_bytes()).into();
        let spending_limit_salt: [u8; 32] = Sha256::digest(spending_limit.as_bytes()).into();
        assert_ne!(simple_salt, weighted_salt);
        assert_ne!(simple_salt, spending_limit_salt);
        assert_ne!(weighted_salt, spending_limit_salt);
    }

    /// The runtime SHA gate for the simple-threshold WASM passes for the
    /// embedded bytes (positive-path unit check; the negative path is
    /// exercised end-to-end by the deploy body's error return).
    #[test]
    fn simple_threshold_runtime_sha_gate_passes_for_embedded_wasm() {
        let mut h = Sha256::new();
        h.update(THRESHOLD_POLICY_WASM);
        let actual = to_hex(&h.finalize());
        assert_eq!(actual, to_hex(&THRESHOLD_POLICY_WASM_HASHES[0]));
    }

    /// The runtime SHA gate for the weighted-threshold WASM passes for the
    /// embedded bytes.
    #[test]
    fn weighted_threshold_runtime_sha_gate_passes_for_embedded_wasm() {
        let mut h = Sha256::new();
        h.update(WEIGHTED_THRESHOLD_POLICY_WASM);
        let actual = to_hex(&h.finalize());
        assert_eq!(actual, WEIGHTED_THRESHOLD_POLICY_WASM_SHA256);
    }

    /// `DeployerKeypair::from_signer` wrapping a fixed-seed software signer;
    /// returns `(g_strkey, deployer)`.
    async fn fixed_seed_deployer(seed: [u8; 32], label: &str) -> (String, DeployerKeypair) {
        use stellar_agent_network::{Signer as _, SoftwareSigningKey};
        use zeroize::Zeroizing;

        let signer = SoftwareSigningKey::new_from_zeroizing(Zeroizing::new(seed));
        // `.to_string()` on `stellar_strkey::ed25519::PublicKey` resolves to a
        // heapless `StringInner` in this workspace (multiple `stellar-strkey`
        // versions coexist); `.as_str().to_owned()` forces the real
        // `std::string::String`.
        let g_strkey = signer
            .public_key()
            .await
            .expect("public_key must succeed")
            .to_string()
            .as_str()
            .to_owned();
        (
            g_strkey,
            DeployerKeypair::from_signer(label.to_owned(), Box::new(signer)),
        )
    }

    /// `already_deployed` MUST return the registry's recorded address, not a
    /// freshly re-derived one: the salt derivation is keyed on the CALLING
    /// deployer, so a different deployer re-running `deploy_policy` against a
    /// registry populated by the FIRST deployer would otherwise get back an
    /// address that was never actually deployed on-chain.
    #[tokio::test]
    async fn already_deployed_returns_registry_address_not_caller_derived_address_on_deployer_mismatch()
     {
        let passphrase = "Test SDF Network ; September 2015";
        let (deployer_a_g, _deployer_a) = fixed_seed_deployer([0x11u8; 32], "deployer-a").await;
        let (_deployer_b_g, deployer_b) = fixed_seed_deployer([0x22u8; 32], "deployer-b").await;

        let wasm_sha256 = to_hex(&THRESHOLD_POLICY_WASM_HASHES[0]);
        let salt_input = format!("{SIMPLE_THRESHOLD_SALT_DOMAIN_PREFIX}{passphrase}");
        let salt: [u8; 32] = Sha256::digest(salt_input.as_bytes()).into();
        let deployer_a_address = derive_smart_account_address(&deployer_a_g, &salt, passphrase)
            .expect("deployer A address derivation must succeed");

        let tmp = tempfile::tempdir().expect("tempdir must succeed");
        let registry_path = tmp.path().join("networks.toml");
        {
            let mut registry = VerifierRegistry::open_at(registry_path.clone())
                .expect("registry open must succeed");
            registry
                .record_simple_threshold_policy(
                    passphrase,
                    deployer_a_address.clone(),
                    wasm_sha256.clone(),
                )
                .expect("recording deployer A's entry must succeed");
            registry.persist().expect("registry persist must succeed");
        }

        let result = deploy_policy(
            PolicyDeployArgs {
                kind: PolicyDeployKind::SimpleThreshold,
                deployer: deployer_b,
                network_passphrase: passphrase.to_owned(),
                rpc_url: "http://127.0.0.1:1".to_owned(),
                timeout: Duration::from_secs(1),
                fee: ResolvedFeePerOp {
                    stroops: 1_000_000,
                    percentile_label: "explicit".to_owned(),
                },
                dry_run: false,
                registry_path_override: Some(registry_path),
            },
            None,
        )
        .await
        .expect("already_deployed path must succeed without any network access");

        assert_eq!(
            result.status, "already_deployed",
            "matching sha256 must short-circuit to already_deployed"
        );
        assert_eq!(
            result.policy_address, deployer_a_address,
            "already_deployed must return the REGISTRY's recorded address (deployer A's), \
             not one re-derived from deployer B's (the caller's) pubkey"
        );
    }
}
