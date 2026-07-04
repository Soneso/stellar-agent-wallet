//! OZ `timelock-controller-example` v0.7.2 contract deployment.
//!
//! Deploys the vendored OZ `timelock_controller_example.wasm`
//! to a Stellar network. Unlike the WebAuthn-verifier deploy, the timelock controller
//! has a `__constructor` with role-setup arguments and is not recorded in a registry
//! (each deployment is distinct per role set + passphrase).
//!
//! # Deploy flow
//!
//! 1. **Runtime SHA gate**: re-verify `sha256(TIMELOCK_CONTROLLER_WASM) ==
//!    TIMELOCK_CONTROLLER_WASM_SHA256` before any submission.
//! 2. **Salt derivation**: `SHA256("oz-timelock-controller-v0.7.2-" || network_passphrase
//!    || first_proposer_strkey_or_empty)`. Including the first proposer in the domain
//!    separates deployments per-role-set on the same network and deployer.
//! 3. **Idempotency check**: attempt `getLedgerEntries` on the derived contract address.
//!    If the contract instance already exists, return `already_deployed` immediately.
//! 4. **Upload WASM** (conditional on WASM not already on-chain) via
//!    `HostFunction::UploadContractWasm`. Calls `simulate_transaction_envelope`,
//!    then assembles the final transaction with resource fee and `SorobanTransactionData`
//!    injected from the simulation response before signing and submitting.
//! 5. **Deploy** via `HostFunction::CreateContractV2` with constructor args:
//!    `(min_delay: u32, proposers: Vec<Address>, executors: Vec<Address>,
//!    admin: Option<Address>)`.
//! 6. **Return** the derived C-strkey.
//!
//! # Constructor args (OZ timelock-controller v0.7.2)
//!
//! Per `examples/timelock-controller/src/contract.rs:242-265` (SHA `a9c4216`):
//! - `min_delay: u32` — minimum ledger delay before ops can execute.
//! - `proposers: Vec<Address>` — accounts granted PROPOSER + CANCELLER roles.
//! - `executors: Vec<Address>` — accounts granted EXECUTOR role; empty = open execution.
//! - `admin: Option<Address>` — initial admin for role management; `None` = no external admin.
//!
//! # ScVal encoding (byte-layout citations)
//!
//! - `u32` → `ScVal::U32` per XDR `Stellar-types.x` (soroban-sdk `IntoVal<Env, Val>` for `u32`).
//! - `Vec<Address>` → `ScVal::Vec(Some(ScVec([ScVal::Address(...), ...])))` per soroban-sdk
//!   `IntoVal` for `Vec<T>` (confirmed at `timelock.rs:858` same crate).
//! - `Option<Address>` → `ScVal::Address(...)` for `Some(a)`, `ScVal::Void` for `None`
//!   (soroban stdlib `Option<T>` Val ABI; NOT the contracttype enum form).
//!

use std::time::Duration;

use sha2::{Digest as _, Sha256};
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
    PublicKey as XdrPublicKey, ScAddress, ScVal, ScVec, SorobanAuthorizationEntry, Uint256, VecM,
    WriteXdr,
};
use tracing::info;

use crate::SaError;
use crate::deployment::address::derive_smart_account_address;
use crate::deployment::deploy::{ResolvedFeePerOp, decode_hex32, redact_wasm_hash, to_hex};
use crate::managers::rules::parse_c_strkey_to_smart_account;

// ── Embedded WASM ─────────────────────────────────────────────────────────────

/// Vendored OZ `timelock-controller-example` v0.7.2 WASM.
///
/// Built from SHA `a9c4216` via `vendor/oz-timelock-controller/v0.7.2/build.sh`.
/// New timelock deployments use these v0.7.2 bytes; the ABI is unchanged from
/// v0.7.1.
pub const TIMELOCK_CONTROLLER_WASM: &[u8] = include_bytes!(
    "../../../../vendor/oz-timelock-controller/v0.7.2/timelock_controller_example.wasm"
);

/// SHA-256 of [`TIMELOCK_CONTROLLER_WASM`], 64-char lowercase hex.
///
/// Matches `ef360d61a44648176f0aae923b9884c6ac5e5a9229af5eb8ab120e81cc4cc1f4`.
/// The `build.rs` gate in this crate asserts this at compile time.
pub const TIMELOCK_CONTROLLER_WASM_SHA256: &str =
    "ef360d61a44648176f0aae923b9884c6ac5e5a9229af5eb8ab120e81cc4cc1f4";

/// Salt domain-separator prefix for the deterministic deploy salt.
///
/// Salt = `SHA256(TIMELOCK_SALT_DOMAIN_PREFIX || network_passphrase || first_proposer_or_empty)`.
/// Including the first proposer separates deployments per role-set on the same network.
///
/// The version suffix pins the salt to the vendored OZ WASM version, so a version bump
/// derives a different address even for the same network + deployer + role-set. This
/// keeps a new v0.7.2 deployment from colliding on-chain with a v0.7.1 timelock the same
/// deployer already deployed at the v0.7.1-domain address, and leaves that v0.7.1
/// timelock valid on-chain. Bumping the vendored WASM version bumps this literal.
const TIMELOCK_SALT_DOMAIN_PREFIX: &str = "oz-timelock-controller-v0.7.2-";

// ── Public types ──────────────────────────────────────────────────────────────

/// Arguments for [`deploy_timelock_controller`].
pub struct TimelockControllerDeployArgs {
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
    /// Minimum ledger delay before operations can execute.
    ///
    /// 0 = operations become executable immediately after scheduling.
    pub min_delay: u32,
    /// Accounts to grant PROPOSER + CANCELLER roles.
    ///
    /// Provide as G-strkeys; they will be encoded as `ScVal::Address`.
    pub proposers: Vec<String>,
    /// Accounts to grant EXECUTOR role.
    ///
    /// Empty vec = open execution (anyone can execute ready operations).
    /// Provide as G-strkeys or C-strkeys.
    pub executors: Vec<String>,
    /// Optional admin account for initial role management.
    ///
    /// `None` = no external admin (the contract governs itself from deploy).
    /// Provide as a G-strkey when `Some`.
    pub admin: Option<String>,
    /// If `true`, compute and return the derived contract address without network access.
    pub dry_run: bool,
}

/// Result of a successful [`deploy_timelock_controller`] call.
#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
pub struct TimelockControllerDeployResult {
    /// Deployed (or existing) timelock controller contract C-strkey.
    pub contract_address: String,
    /// SHA-256 of the deployed WASM, 64-char lowercase hex.
    pub wasm_sha256: String,
    /// Stellar network passphrase for which the controller was deployed.
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

/// Deploys the vendored OZ `timelock-controller-example` v0.7.2 contract.
///
/// See the module-level documentation for the full deploy flow.
///
/// # Errors
///
/// - [`SaError::DeploymentFailed`] — runtime SHA gate mismatch, encoding failure,
///   or Soroban deployment failed at one of the 7 canonical phases.
///
/// # Panics
///
/// Never panics. The runtime SHA gate returns `Err` on mismatch rather than
/// panicking; the compile-time `build.rs` gate prevents mismatched WASM from
/// reaching the binary.
pub async fn deploy_timelock_controller(
    args: TimelockControllerDeployArgs,
) -> Result<TimelockControllerDeployResult, SaError> {
    deploy_timelock_controller_body(args).await
}

// ── Deploy body ───────────────────────────────────────────────────────────────

async fn deploy_timelock_controller_body(
    args: TimelockControllerDeployArgs,
) -> Result<TimelockControllerDeployResult, SaError> {
    // ── Step 1: Runtime SHA gate ──────────────────────────────────────────────
    // The compile-time build.rs gate and this unconditional runtime check are sufficient.
    {
        let mut h = Sha256::new();
        h.update(TIMELOCK_CONTROLLER_WASM);
        let actual = to_hex(&h.finalize());
        if actual != TIMELOCK_CONTROLLER_WASM_SHA256 {
            return Err(SaError::DeploymentFailed {
                phase: "build",
                redacted_reason: format!(
                    "timelock-controller WASM SHA256 mismatch: expected \
                     {TIMELOCK_CONTROLLER_WASM_SHA256}, got {actual}"
                ),
            });
        }
    }

    let wasm_hash_bytes: [u8; 32] =
        decode_hex32(TIMELOCK_CONTROLLER_WASM_SHA256).map_err(|()| SaError::DeploymentFailed {
            phase: "build",
            redacted_reason: "TIMELOCK_CONTROLLER_WASM_SHA256 const is not valid 64-char hex"
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

    // ── Step 3: Deterministic salt ────────────────────────────────────────────
    //
    // Salt = SHA256("oz-timelock-controller-v0.7.2-" || network_passphrase ||
    //               first_proposer_or_empty).
    // Including the first proposer separates deployments per role-set on the same
    // network + deployer.
    let first_proposer = args.proposers.first().map(String::as_str).unwrap_or("");
    let salt_input = format!(
        "{TIMELOCK_SALT_DOMAIN_PREFIX}{}{}",
        args.network_passphrase, first_proposer
    );
    let salt: [u8; 32] = Sha256::digest(salt_input.as_bytes()).into();
    let salt_hex = to_hex(&salt);

    // ── Step 4: Derive expected contract C-strkey ─────────────────────────────
    let derived_address =
        derive_smart_account_address(&deployer_pubkey, &salt, &args.network_passphrase).map_err(
            |e| SaError::DeploymentFailed {
                phase: "build",
                redacted_reason: format!("timelock address derivation failed: {e}"),
            },
        )?;

    // ── Dry-run path ──────────────────────────────────────────────────────────
    if args.dry_run {
        return Ok(TimelockControllerDeployResult {
            contract_address: derived_address,
            wasm_sha256: TIMELOCK_CONTROLLER_WASM_SHA256.to_owned(),
            network_passphrase: args.network_passphrase,
            tx_hash: None,
            ledger: None,
            status: "dry_run",
        });
    }

    // ── Step 5: Idempotency check ─────────────────────────────────────────────
    let rpc_server = Client::new(&args.rpc_url).map_err(|e| SaError::DeploymentFailed {
        phase: "build",
        redacted_reason: format!("rpc-server construction failed: {e}"),
    })?;

    let network_client =
        StellarRpcClient::new(&args.rpc_url).map_err(|e| SaError::DeploymentFailed {
            phase: "build",
            redacted_reason: format!("StellarRpcClient construction failed: {e}"),
        })?;

    // Check if the contract instance already exists at the derived address.
    if let Ok(c_strkey) = ContractStrkey::from_string(&derived_address) {
        let contract_sc_address = ScAddress::Contract(ContractId(Hash(c_strkey.0)));
        let instance_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: contract_sc_address,
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        });
        if let Ok(resp) = rpc_server.get_ledger_entries(&[instance_key]).await
            && resp.entries.as_ref().is_some_and(|e| !e.is_empty())
        {
            info!(
                contract = %stellar_agent_core::observability::redact_strkey_first5_last5(
                    &derived_address),
                network = &args.network_passphrase,
                "deploy_timelock_controller: already deployed; returning existing entry"
            );
            return Ok(TimelockControllerDeployResult {
                contract_address: derived_address,
                wasm_sha256: TIMELOCK_CONTROLLER_WASM_SHA256.to_owned(),
                network_passphrase: args.network_passphrase,
                tx_hash: None,
                ledger: None,
                status: "already_deployed",
            });
        }
    }

    // ── Step 6: Fetch deployer account sequence ───────────────────────────────
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

    // ── Step 7: Upload WASM (conditional) ─────────────────────────────────────
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

    let wasm_already_on_chain = wasm_query_resp
        .entries
        .as_ref()
        .is_some_and(|e| !e.is_empty());

    if !wasm_already_on_chain {
        info!(
            wasm_hash = %redact_wasm_hash(TIMELOCK_CONTROLLER_WASM_SHA256),
            "deploy_timelock_controller: uploading WASM"
        );

        let wasm_bytes: BytesM = TIMELOCK_CONTROLLER_WASM.to_vec().try_into().map_err(|_| {
            SaError::DeploymentFailed {
                phase: "build",
                redacted_reason: "TIMELOCK_CONTROLLER_WASM exceeds BytesM maximum length"
                    .to_owned(),
            }
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

        // Assemble the prepared upload transaction from simulation results.
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
        .map_err(|e| SaError::DeploymentFailed {
            phase: "upload",
            redacted_reason: format!("upload submission failed: {e}"),
        })?;

        info!(
            upload_tx_hash = %stellar_agent_network::redact_tx_hash(&upload_submission.tx_hash),
            ledger = upload_submission.ledger,
            "deploy_timelock_controller: WASM uploaded"
        );

        // Re-fetch deployer sequence after the upload transaction.
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
    } else {
        info!(
            wasm_hash = %redact_wasm_hash(TIMELOCK_CONTROLLER_WASM_SHA256),
            "deploy_timelock_controller: WASM already on-chain; skipping upload"
        );
    }

    // ── Step 8: Build constructor args ─────────────────────────────────────────
    //
    // OZ __constructor(e, min_delay: u32, proposers: Vec<Address>,
    //                  executors: Vec<Address>, admin: Option<Address>)
    // examples/timelock-controller/src/contract.rs:242-265 (SHA a9c4216).

    // proposers: Vec<Address> → ScVal::Vec(Some(ScVec([ScVal::Address(...)...])))
    let proposers_scvals: Result<Vec<ScVal>, SaError> = args
        .proposers
        .iter()
        .map(|g| {
            parse_c_strkey_to_smart_account(g)
                .map(ScVal::Address)
                .or_else(|_| {
                    // Try as G-strkey (Account)
                    stellar_strkey::ed25519::PublicKey::from_string(g)
                        .map_err(|e| SaError::DeploymentFailed {
                            phase: "build",
                            redacted_reason: format!("proposer strkey parse failed: {e:?}"),
                        })
                        .map(|pk| {
                            ScVal::Address(ScAddress::Account(AccountId(
                                XdrPublicKey::PublicKeyTypeEd25519(Uint256(pk.0)),
                            )))
                        })
                })
        })
        .collect();
    let proposers_scvals = proposers_scvals?;
    let proposers_vecm: VecM<ScVal> =
        proposers_scvals
            .try_into()
            .map_err(|e| SaError::DeploymentFailed {
                phase: "build",
                redacted_reason: format!("proposers VecM encoding failed: {e:?}"),
            })?;
    let proposers_scval = ScVal::Vec(Some(ScVec(proposers_vecm)));

    // executors: Vec<Address>
    let executors_scvals: Result<Vec<ScVal>, SaError> = args
        .executors
        .iter()
        .map(|g| {
            parse_c_strkey_to_smart_account(g)
                .map(ScVal::Address)
                .or_else(|_| {
                    stellar_strkey::ed25519::PublicKey::from_string(g)
                        .map_err(|e| SaError::DeploymentFailed {
                            phase: "build",
                            redacted_reason: format!("executor strkey parse failed: {e:?}"),
                        })
                        .map(|pk| {
                            ScVal::Address(ScAddress::Account(AccountId(
                                XdrPublicKey::PublicKeyTypeEd25519(Uint256(pk.0)),
                            )))
                        })
                })
        })
        .collect();
    let executors_scvals = executors_scvals?;
    let executors_vecm: VecM<ScVal> =
        executors_scvals
            .try_into()
            .map_err(|e| SaError::DeploymentFailed {
                phase: "build",
                redacted_reason: format!("executors VecM encoding failed: {e:?}"),
            })?;
    let executors_scval = ScVal::Vec(Some(ScVec(executors_vecm)));

    // admin: Option<Address>
    // Soroban stdlib Option<T> ABI: Some(v) = raw inner ScVal, None = ScVal::Void
    let admin_scval = match &args.admin {
        Some(g) => {
            let pk = stellar_strkey::ed25519::PublicKey::from_string(g).map_err(|e| {
                SaError::DeploymentFailed {
                    phase: "build",
                    redacted_reason: format!("admin strkey parse failed: {e:?}"),
                }
            })?;
            ScVal::Address(ScAddress::Account(AccountId(
                XdrPublicKey::PublicKeyTypeEd25519(Uint256(pk.0)),
            )))
        }
        None => ScVal::Void,
    };

    let constructor_args: VecM<ScVal> = vec![
        ScVal::U32(args.min_delay),
        proposers_scval,
        executors_scval,
        admin_scval,
    ]
    .try_into()
    .map_err(|e| SaError::DeploymentFailed {
        phase: "build",
        redacted_reason: format!("constructor_args VecM encoding failed: {e:?}"),
    })?;

    // ── Step 9: Build CreateContractV2 deploy transaction ─────────────────────
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

    // Assemble the prepared deploy transaction from simulation results.
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
        wasm_hash = %redact_wasm_hash(TIMELOCK_CONTROLLER_WASM_SHA256),
        "deploy_timelock_controller: submitting deploy transaction"
    );

    let submission = submit_transaction_and_wait(
        &network_client,
        &signed_xdr,
        args.timeout,
        &args.network_passphrase,
        None,
    )
    .await
    .map_err(|e| SaError::DeploymentFailed {
        phase: "deploy",
        redacted_reason: format!("deploy submission failed: {e}"),
    })?;

    info!(
        contract = %stellar_agent_core::observability::redact_strkey_first5_last5(&derived_address),
        tx_hash = %stellar_agent_network::redact_tx_hash(&submission.tx_hash),
        ledger = submission.ledger,
        "deploy_timelock_controller: deployment confirmed"
    );

    Ok(TimelockControllerDeployResult {
        contract_address: derived_address,
        wasm_sha256: TIMELOCK_CONTROLLER_WASM_SHA256.to_owned(),
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

    use sha2::{Digest as _, Sha256};

    use super::*;

    /// Asserts the runtime SHA gate passes for the embedded WASM.
    #[test]
    fn runtime_sha_gate_passes_for_embedded_wasm() {
        let mut h = Sha256::new();
        h.update(TIMELOCK_CONTROLLER_WASM);
        let actual = to_hex(&h.finalize());
        assert_eq!(
            actual, TIMELOCK_CONTROLLER_WASM_SHA256,
            "runtime sha gate must pass for the embedded WASM bytes"
        );
    }

    /// Asserts salt derivation differs by network passphrase + proposer.
    #[test]
    fn deterministic_salt_differs_by_proposer_and_passphrase() {
        let testnet = "Test SDF Network ; September 2015";
        let mainnet = "Public Global Stellar Network ; September 2015";
        let proposer_a = "GDUMMY_PROPOSER_A";
        let proposer_b = "GDUMMY_PROPOSER_B";

        let make_salt = |passphrase: &str, proposer: &str| -> [u8; 32] {
            let s = format!("{TIMELOCK_SALT_DOMAIN_PREFIX}{passphrase}{proposer}");
            Sha256::digest(s.as_bytes()).into()
        };

        let salt1 = make_salt(testnet, proposer_a);
        let salt2 = make_salt(testnet, proposer_b);
        let salt3 = make_salt(mainnet, proposer_a);
        let salt4 = make_salt(testnet, proposer_a); // same as salt1

        assert_ne!(
            salt1, salt2,
            "different proposers must produce different salts"
        );
        assert_ne!(
            salt1, salt3,
            "different passphrases must produce different salts"
        );
        assert_eq!(salt1, salt4, "same inputs must produce the same salt");
    }
}
