//! Ed25519-verifier contract deployment via Soroban `CreateContractV2`.
//!
//! Deploys the vendored OZ `multisig_ed25519_verifier_example.wasm` to a Stellar
//! network and records the resulting contract address in the wallet-local
//! [`VerifierRegistry`] (`~/.config/stellar-agent/networks.toml`).
//!
//! # Deploy flow
//!
//! 1. **Runtime SHA gate**: re-verify
//!    `sha256(ED25519_VERIFIER_WASM) == ED25519_VERIFIER_WASM_SHA256` before any
//!    submission.  Refuses with [`SaError::Ed25519VerifierProvenanceMismatch`] on
//!    mismatch.  The `include_bytes!`-baked `&'static [u8]` is the same slice
//!    passed to `UploadContractWasm`; no TOCTOU window exists.
//! 2. **Idempotency check**: open the [`VerifierRegistry`]; if an Ed25519-verifier
//!    entry already exists for the target network with the same `wasm_sha256`,
//!    return immediately with `status: "already_deployed"` and no RPC traffic.
//! 3. **Deploy**: `UploadContractWasm` (conditional on WASM not already on-chain) +
//!    `CreateContractV2(args: [])`.  The verifier has no `__constructor`; no
//!    constructor args required.  Confirmed from OZ
//!    `examples/multisig-smart-account/ed25519-verifier/src/contract.rs:14-70`
//!    (SHA `a9c4216`) and `vendor/oz-ed25519-verifier/v0.7.2/PROVENANCE.md`, which
//!    export only `verify`, `canonicalize_key`, and `batch_canonicalize_key`.
//! 4. **Record**: invoke [`VerifierRegistry::record_ed25519_verifier`] + persist.
//! 5. **Audit-log**: emit `SaRawInvocation` with `operation: "deploy_ed25519_verifier"`.
//!
//! # Deterministic salt
//!
//! Salt = `SHA256("oz-ed25519-verifier-v0.7.2-" || network_passphrase)`.
//! Using the WASM version string + passphrase as a salt domain means the same
//! deployer + WASM version will always produce the same contract address for a
//! given network.  A future WASM version bump changes the domain and thus the
//! address.
//!
//! # Mainnet guard
//!
//! The CLI handler structurally refuses mainnet BEFORE calling this function.
//! An additional passphrase check fires at `submit_transaction_and_wait`.
//!
//! # Reference cross-check
//!
//! - OZ `examples/multisig-smart-account/ed25519-verifier/src/contract.rs:14-70`
//!   (SHA `a9c4216`) — the contract whose WASM this deploys; no `__constructor`.
//! - `deployment/deploy.rs` — reuses `submit_transaction_and_wait`,
//!   `verify_post_deploy_wasm_hash`, `to_hex`, `decode_hex32`, `redact_wasm_hash`,
//!   fee + RPC helpers; mirrors the two-tx split pattern.

use std::time::Duration;

use sha2::{Digest as _, Sha256};
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::SaInvocationResult;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::error::{SubmissionError, WalletError};
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
    ResolvedFeePerOp, caip2_chain_id_for_passphrase, decode_hex32, redact_wasm_hash, to_hex,
    uuid_v4_hex, verify_post_deploy_wasm_hash,
};
use crate::ed25519_verifier::{ED25519_VERIFIER_WASM, ED25519_VERIFIER_WASM_SHA256};
use crate::verifiers::VerifierRegistry;

/// Deterministic-salt domain-prefix string for the Ed25519-verifier deploy.
///
/// The deterministic salt is `SHA256(VERIFIER_SALT_DOMAIN_PREFIX || network_passphrase)`.
/// The version suffix in the prefix pins the salt to the OZ WASM version, so a
/// future verifier bump produces a different address even on the same network
/// with the same deployer.  Pinned to a single `const` so a version bump touches
/// one site.
const VERIFIER_SALT_DOMAIN_PREFIX: &str = "oz-ed25519-verifier-v0.7.2-";

// ── Public types ──────────────────────────────────────────────────────────────

/// Arguments for [`deploy_ed25519_verifier`].
pub struct Ed25519VerifierDeployArgs {
    /// Deployer keypair (same three-mode shape as `DeploymentArgs::deployer`).
    pub deployer: crate::deployment::deploy::DeployerKeypair,
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
    ///
    /// Populated by CLI tests via `STELLAR_AGENT_NETWORKS_TOML` env-var; production callers
    /// leave this `None` and rely on the env-var / OS-convention resolution inside
    /// [`VerifierRegistry::open`].
    pub registry_path_override: Option<std::path::PathBuf>,
}

/// Result of a successful [`deploy_ed25519_verifier`] call.
#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
pub struct Ed25519VerifierDeployResult {
    /// Deployed (or existing) verifier contract C-strkey.
    pub verifier_address: String,
    /// SHA-256 of the deployed WASM, 64-char lowercase hex.
    pub verifier_wasm_sha256: String,
    /// Stellar network passphrase for which the verifier was deployed.
    pub network_passphrase: String,
    /// Transaction hash of the `CreateContractV2` deploy transaction.
    ///
    /// `None` when `already_deployed` or `dry_run`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    /// Confirmed ledger sequence.  `None` when `already_deployed` or `dry_run`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ledger: Option<u32>,
    /// Outcome label: `"deployed"`, `"already_deployed"`, or `"dry_run"`.
    pub status: &'static str,
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Deploys the vendored OZ Ed25519-verifier contract and records the address in
/// the wallet-local [`VerifierRegistry`].
///
/// See the module-level documentation for the full deploy flow.
///
/// # Errors
///
/// - [`SaError::Ed25519VerifierProvenanceMismatch`] — runtime SHA gate failed.
/// - [`SaError::NetworksTomlIo`] — registry read/write failed.
/// - [`SaError::NetworksTomlParse`] — registry TOML invalid.
/// - [`SaError::Ed25519VerifierSha256Drift`] — registry has different sha256 for network.
/// - [`SaError::DeploymentFailed`] — Soroban deployment failed at one of the 7 canonical phases.
///
/// # Panics
///
/// Never panics in release mode.  `debug_assert!` fires in debug builds if the embedded
/// WASM bytes do not match `ED25519_VERIFIER_WASM_SHA256`.
pub async fn deploy_ed25519_verifier(
    args: Ed25519VerifierDeployArgs,
    audit_writer: Option<&mut AuditWriter>,
) -> Result<Ed25519VerifierDeployResult, SaError> {
    let chain_id = caip2_chain_id_for_passphrase(&args.network_passphrase);
    let is_dry_run = args.dry_run;

    let outcome = deploy_ed25519_verifier_body(args).await;

    // Audit-log emission (mirrors deploy_smart_account pattern; no auth_digest on deploy ops).
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
                    &result.verifier_address,
                ),
            ),
            Err(e) => (e.wire_code(), "unknown".to_owned()),
        };

        // Emit SaRawInvocation for the deploy_ed25519_verifier operation.
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
                "deploy_ed25519_verifier: SaRawInvocation audit write failed"
            );
        }
    }

    outcome
}

// ── Deploy body (no audit writes) ────────────────────────────────────────────

async fn deploy_ed25519_verifier_body(
    args: Ed25519VerifierDeployArgs,
) -> Result<Ed25519VerifierDeployResult, SaError> {
    // ── Step 1: Runtime SHA gate ──────────────────────────────────────────────
    //
    // Re-compute SHA-256 of the in-memory WASM bytes at deploy time.  The same
    // `&'static [u8]` slice is subsequently passed to `UploadContractWasm`, so there
    // is no TOCTOU window between the hash-check and the submission.
    //
    // Also runs as a debug_assert in debug builds per the supply-chain integrity pattern
    // from deploy.rs (the cargo test compile-time gate in ed25519_verifier.rs is the
    // first line of defence).
    #[cfg(debug_assertions)]
    {
        let mut h = Sha256::new();
        h.update(ED25519_VERIFIER_WASM);
        let observed = to_hex(&h.finalize());
        debug_assert_eq!(
            observed, ED25519_VERIFIER_WASM_SHA256,
            "ED25519_VERIFIER_WASM bytes do not match the compile-time pin; \
             re-run vendor/oz-ed25519-verifier/v0.7.2/build.sh"
        );
    }
    {
        let mut h = Sha256::new();
        h.update(ED25519_VERIFIER_WASM);
        let actual = to_hex(&h.finalize());
        if actual != ED25519_VERIFIER_WASM_SHA256 {
            return Err(SaError::Ed25519VerifierProvenanceMismatch {
                expected: ED25519_VERIFIER_WASM_SHA256.to_owned(),
                actual,
            });
        }
    }

    // Parse WASM hash bytes once for use in LedgerKey construction.
    let wasm_hash_bytes: [u8; 32] =
        decode_hex32(ED25519_VERIFIER_WASM_SHA256).map_err(|()| SaError::DeploymentFailed {
            phase: "build",
            redacted_reason: "ED25519_VERIFIER_WASM_SHA256 const is not valid 64-char hex"
                .to_owned(),
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
    //
    // Salt = SHA256(VERIFIER_SALT_DOMAIN_PREFIX || network_passphrase).
    // The domain prefix pins the salt to the WASM version + network so the same
    // deployer produces the same address for this WASM version on this network.
    let salt_input = format!("{VERIFIER_SALT_DOMAIN_PREFIX}{}", args.network_passphrase);
    let salt: [u8; 32] = Sha256::digest(salt_input.as_bytes()).into();
    let salt_hex = to_hex(&salt);

    // ── Step 4: Derive the expected verifier C-strkey (pure, no network) ──────
    let derived_verifier_address =
        derive_smart_account_address(&deployer_pubkey, &salt, &args.network_passphrase).map_err(
            |e| SaError::DeploymentFailed {
                phase: "build",
                redacted_reason: format!("verifier address derivation failed: {e}"),
            },
        )?;

    // ── Dry-run path ──────────────────────────────────────────────────────────
    if args.dry_run {
        return Ok(Ed25519VerifierDeployResult {
            verifier_address: derived_verifier_address,
            verifier_wasm_sha256: ED25519_VERIFIER_WASM_SHA256.to_owned(),
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

    if let Some(existing) = registry.ed25519_verifier_for(&args.network_passphrase) {
        if existing.wasm_sha256 == ED25519_VERIFIER_WASM_SHA256 {
            info!(
                verifier = %stellar_agent_core::observability::redact_strkey_first5_last5(
                    &existing.address),
                network = &args.network_passphrase,
                "deploy_ed25519_verifier: already deployed; returning existing entry"
            );
            return Ok(Ed25519VerifierDeployResult {
                verifier_address: existing.address.clone(),
                verifier_wasm_sha256: existing.wasm_sha256.clone(),
                network_passphrase: args.network_passphrase,
                tx_hash: None,
                ledger: None,
                status: "already_deployed",
            });
        }
        // Different sha256 → sha256-drift guard fires.
        return Err(SaError::Ed25519VerifierSha256Drift {
            network: args.network_passphrase,
            recorded: existing.wasm_sha256.clone(),
            attempted: ED25519_VERIFIER_WASM_SHA256.to_owned(),
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
    let deployer_view = fetch_account(&network_client, &deployer_pubkey, &[])
        .await
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

    let wasm_query_resp = rpc_server
        .get_ledger_entries(&[wasm_key])
        .await
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
            wasm_hash = %redact_wasm_hash(ED25519_VERIFIER_WASM_SHA256),
            "deploy_ed25519_verifier: WASM already on-chain; skipping upload"
        );
        None
    } else {
        info!(
            wasm_hash = %redact_wasm_hash(ED25519_VERIFIER_WASM_SHA256),
            "deploy_ed25519_verifier: uploading WASM"
        );

        let wasm_bytes: BytesM =
            ED25519_VERIFIER_WASM
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
        let upload_sim = rpc_server
            .simulate_transaction_envelope(&upload_envelope, None)
            .await
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

        let upload_submission = submit_transaction_and_wait(
            &network_client,
            &signed_upload_xdr,
            args.timeout,
            &args.network_passphrase,
            None,
        )
        .await
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
            upload_tx_hash = %stellar_agent_network::redact_tx_hash(&upload_submission.tx_hash),
            ledger = upload_submission.ledger,
            "deploy_ed25519_verifier: WASM uploaded"
        );

        // Re-fetch deployer sequence number after the upload transaction.
        let deployer_view2 = fetch_account(&network_client, &deployer_pubkey, &[])
            .await
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
    // The OZ Ed25519 verifier has NO `__constructor` — it exports only `verify`,
    // `canonicalize_key`, `batch_canonicalize_key`.  Constructor args must be empty.
    // Cross-check: OZ `examples/multisig-smart-account/ed25519-verifier/src/contract.rs:14-70`
    // (SHA `a9c4216`) and `vendor/oz-ed25519-verifier/v0.7.2/PROVENANCE.md` — no
    // `__constructor` function in the contract impl.
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

    // Empty constructor args for the verifier contract.
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
    let sim_response = rpc_server
        .simulate_transaction_envelope(&deploy_envelope_pre, None)
        .await
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
    // CreateContractV2 from the deployer address requires the SourceAccount-credential
    // authorization entry the simulation computes. Attach the simulated auth entries to
    // the single InvokeHostFunction operation before signing; without them the on-chain
    // host-function execution is unauthorized and traps.
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
        deployer = %stellar_agent_core::observability::redact_strkey_first5_last5(&deployer_pubkey),
        salt = %stellar_agent_core::hex::redact_hex_first8_last8(&salt_hex),
        wasm_hash = %redact_wasm_hash(ED25519_VERIFIER_WASM_SHA256),
        "deploy_ed25519_verifier: submitting deploy transaction"
    );

    let submission = submit_transaction_and_wait(
        &network_client,
        &signed_xdr,
        args.timeout,
        &args.network_passphrase,
        None,
    )
    .await
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
    let c_strkey_decoded = ContractStrkey::from_string(&derived_verifier_address).map_err(|e| {
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

    let post_deploy_resp = rpc_server
        .get_ledger_entries(&[instance_key])
        .await
        .map_err(|e| SaError::DeploymentFailed {
            phase: "post_deploy_verification",
            redacted_reason: format!("getLedgerEntries (post-deploy verify) failed: {e}"),
        })?;

    let entries = post_deploy_resp.entries.unwrap_or_default();
    let entry = entries.first().ok_or_else(|| SaError::DeploymentFailed {
        phase: "post_deploy_verification",
        redacted_reason: "post-deploy getLedgerEntries returned no entries".to_owned(),
    })?;

    verify_post_deploy_wasm_hash(
        entry,
        ED25519_VERIFIER_WASM_SHA256,
        &derived_verifier_address,
    )?;

    info!(
        verifier = %stellar_agent_core::observability::redact_strkey_first5_last5(
            &derived_verifier_address),
        tx_hash = %stellar_agent_network::redact_tx_hash(&submission.tx_hash),
        ledger = submission.ledger,
        "deploy_ed25519_verifier: deployment verified"
    );

    // ── Step 13: Record in registry ───────────────────────────────────────────
    let _ = registry.record_ed25519_verifier(
        &args.network_passphrase,
        derived_verifier_address.clone(),
        ED25519_VERIFIER_WASM_SHA256.to_owned(),
    )?;
    registry.persist()?;

    // Suppress upload_tx_hash in result (available in tracing logs above if needed).
    // It is not part of the public result envelope.
    let _ = upload_tx_hash;

    Ok(Ed25519VerifierDeployResult {
        verifier_address: derived_verifier_address,
        verifier_wasm_sha256: ED25519_VERIFIER_WASM_SHA256.to_owned(),
        network_passphrase: args.network_passphrase,
        tx_hash: Some(submission.tx_hash),
        ledger: Some(submission.ledger),
        status: "deployed",
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    #![allow(clippy::expect_used, reason = "test-only")]

    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::ed25519_verifier::{ED25519_VERIFIER_WASM, ED25519_VERIFIER_WASM_SHA256};

    /// Asserts the runtime SHA gate fires correctly when the in-memory WASM
    /// bytes match the pinned const.  This is the positive-path assertion;
    /// the negative path is tested via the full deploy flow integration test.
    ///
    /// Uses the same logic as the gate in `deploy_ed25519_verifier_body` to
    /// provide a unit-level confidence check.
    #[test]
    fn runtime_sha_gate_passes_for_embedded_wasm() {
        let mut h = Sha256::new();
        h.update(ED25519_VERIFIER_WASM);
        let actual = to_hex(&h.finalize());
        assert_eq!(
            actual, ED25519_VERIFIER_WASM_SHA256,
            "runtime sha gate must pass for the embedded WASM bytes"
        );
    }

    /// Asserts that the deterministic salt derivation is stable and produces
    /// different values for different inputs.
    #[test]
    fn deterministic_salt_is_stable_and_differs_by_passphrase() {
        let testnet = "Test SDF Network ; September 2015";
        let mainnet = "Public Global Stellar Network ; September 2015";

        let domain_testnet = format!("{VERIFIER_SALT_DOMAIN_PREFIX}{testnet}");
        let domain_mainnet = format!("{VERIFIER_SALT_DOMAIN_PREFIX}{mainnet}");

        let salt_testnet: [u8; 32] = Sha256::digest(domain_testnet.as_bytes()).into();
        let salt_mainnet: [u8; 32] = Sha256::digest(domain_mainnet.as_bytes()).into();

        assert_ne!(
            salt_testnet, salt_mainnet,
            "different passphrases must produce different deterministic salts"
        );

        // Same input → same output (deterministic).
        let salt_testnet2: [u8; 32] = Sha256::digest(domain_testnet.as_bytes()).into();
        assert_eq!(
            salt_testnet, salt_testnet2,
            "salt derivation must be deterministic"
        );
    }

    /// Asserts the Ed25519 salt domain prefix differs from the WebAuthn one so
    /// the two verifiers derive distinct addresses for the same deployer +
    /// network (they are separate contracts).
    #[test]
    fn salt_domain_prefix_differs_from_webauthn() {
        let passphrase = "Test SDF Network ; September 2015";
        let ed25519_domain = format!("{VERIFIER_SALT_DOMAIN_PREFIX}{passphrase}");
        let webauthn_domain = format!("oz-webauthn-verifier-v0.7.2-{passphrase}");

        let ed25519_salt: [u8; 32] = Sha256::digest(ed25519_domain.as_bytes()).into();
        let webauthn_salt: [u8; 32] = Sha256::digest(webauthn_domain.as_bytes()).into();

        assert_ne!(
            ed25519_salt, webauthn_salt,
            "ed25519 and webauthn verifier salts must differ (distinct contracts)"
        );
    }
}
