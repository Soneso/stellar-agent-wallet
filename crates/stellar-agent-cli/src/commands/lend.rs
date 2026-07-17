//! `stellar-agent lend` subcommand — Blend protocol supply/borrow/repay/withdraw.
//!
//! # What this command does
//!
//! Submits one or more supply/borrow/repay/withdraw requests to a Blend v1/v2
//! pool through the wallet's smart-account.  Enforces the ordered trust gate:
//! pool WASM-hash pin, Reflector oracle allowlist, oracle staleness.
//!
//! # Ordered trust gate (LOAD-BEARING)
//!
//! 1. `verify_blend_pool_wasm` — two-RPC pin check against v1/v2 pool WASM set.
//! 2. `read_pool_oracle_address` + oracle-allowlist check.
//! 3. `query_oracle_lastprice_timestamps` + staleness evaluation.
//!
//! Only after all three steps pass, the `lend` verb is dispatched via
//! `dispatch_gate` and `BlendLendAdapter::submit` is called.
//!
//! # Operator policy evaluation
//!
//! The CLI loads the operator-signed `PolicyEngineV1` from the profile (if
//! `policy.engine = "v1"`) or falls back to `NoopPolicyEngine` (if `"noop"`).
//! A `ToolDescriptor` for `stellar_blend_lend` (destructive, not read-only) is
//! evaluated BEFORE submit, value-carrying via `evaluate_with_value` — honouring
//! Deny / RequireApproval exactly as the MCP tool does via
//! `WalletServer::dispatch_gate_with_value`.  The legs are built from the SAME
//! `blend_requests` vector later placed into `BlendLendArgs` (single-decode
//! invariant).  The verb-registry `dispatch_gate` call remains
//! (capability-witness seam); the policy evaluation runs alongside it.  Both
//! paths enforce the operator policy document.
//!
//! # Audit pre-flight (fail-closed)
//!
//! Before the signer is loaded or the lend is submitted, requires the
//! profile's audit chain-root HMAC key to be acquirable via
//! [`crate::commands::value_audit::require_value_audit_writer`], refusing
//! with `audit.chain_key_unavailable` if not — `lend` always loads a
//! persisted `<name>.toml` profile (no zero-config synthesis), so the
//! pre-flight fails closed unconditionally, unlike `pay` / `claim` /
//! `accounts create`. The acquired writer is reused (not re-acquired) for
//! `DefiAdapterCtx::audit_writer`.
//!
//! # Output
//!
//! JSON by default.  Returns `0` on success, `1` on error.

use clap::{Args, ValueEnum};
use serde_json::json;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::WalletError;
use stellar_agent_core::policy::v1::{ValueClass, ValueEffects};
use stellar_agent_core::profile::loader as profile_loader;
use stellar_agent_core::profile::schema::Profile;

use crate::commands::policy_engine::{
    build_v1_policy_engine, evaluate_value_moving_policy_with_value,
};

use stellar_agent_blend::{
    abi::{BlendRequest, LendArgs as BlendLendArgs, RequestType},
    adapter::BlendLendAdapter,
    oracle::OracleStalenessEvalExt,
    oracle::OracleStalenessSnapshot,
    oracle_fetch::{
        PoolOracleFetchError, query_oracle_lastprice_timestamps, read_pool_oracle_address,
    },
    pins::{
        BlendPoolWasmSet, blend_pool_wasm_set_pubnet, blend_pool_wasm_set_testnet,
        is_oracle_in_allowlist, verify_blend_pool_wasm,
    },
    value::blend_value_legs,
};
use stellar_agent_defi::adapter::{DefiAdapter, DefiAdapterCtx};
use stellar_agent_defi::dispatch::{GateOutcome, dispatch_gate, require_approval_error};
use stellar_agent_defi::pins::DefiContractPin;
use stellar_agent_network::{StellarRpcClient, init_platform_keyring_store, signer_from_keyring};

use crate::common::render::render_json;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default oracle staleness threshold in seconds.
const DEFAULT_MAX_STALENESS_SECS: u64 = stellar_agent_blend::oracle::DEFAULT_MAX_STALENESS_SECS;

// ─────────────────────────────────────────────────────────────────────────────
// Argument types
// ─────────────────────────────────────────────────────────────────────────────

/// The operation type for a single Blend request.
#[derive(Debug, Clone, ValueEnum)]
pub enum LendOp {
    /// Supply tokens to the pool's reserve (RequestType 0).
    Supply,
    /// Withdraw tokens from the pool's reserve (RequestType 1).
    Withdraw,
    /// Supply tokens as collateral (RequestType 2).
    #[value(name = "supply-collateral")]
    SupplyCollateral,
    /// Withdraw tokens from collateral (RequestType 3).
    #[value(name = "withdraw-collateral")]
    WithdrawCollateral,
    /// Borrow tokens from the pool's reserve (RequestType 4).
    Borrow,
    /// Repay a borrow (RequestType 5).
    Repay,
}

impl LendOp {
    fn to_request_type(&self) -> RequestType {
        match self {
            LendOp::Supply => RequestType::Supply,
            LendOp::Withdraw => RequestType::Withdraw,
            LendOp::SupplyCollateral => RequestType::SupplyCollateral,
            LendOp::WithdrawCollateral => RequestType::WithdrawCollateral,
            LendOp::Borrow => RequestType::Borrow,
            LendOp::Repay => RequestType::Repay,
        }
    }
}

/// Successful `lend` operation result.
#[derive(Debug, serde::Serialize)]
pub struct LendResult {
    /// Summary of the lend operation.
    pub summary: String,
    /// Oracle staleness age in seconds (display only).
    pub oracle_staleness_secs: Option<u64>,
}

/// Arguments for the `stellar-agent lend` subcommand.
///
/// # Examples
///
/// ```text
/// stellar-agent lend \
///   --pool CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF \
///   --from CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD \
///   --op supply \
///   --asset CAQCFVLOBK5GIULPNZRGATJJMIZL5BSP7X5YJVMGCPTUEPFM4AVSRCJU \
///   --amount 500000000 \
///   --profile default
/// ```
#[derive(Debug, Args)]
pub struct LendArgs {
    /// Profile name to load (default: "default").
    #[arg(long, default_value = "default")]
    pub profile: String,

    /// The Blend pool contract address (C-strkey).
    #[arg(long)]
    pub pool: String,

    /// The wallet smart-account address (C-strkey).
    #[arg(long)]
    pub from: String,

    /// The operation type.
    #[arg(long, value_enum)]
    pub op: LendOp,

    /// The asset contract address (C-strkey).
    #[arg(long)]
    pub asset: String,

    /// Amount in the asset's native base unit (integer, no decimals).
    #[arg(long)]
    pub amount: i128,

    /// Override oracle staleness check (default false).
    #[arg(long, default_value_t = false)]
    pub override_oracle_staleness: bool,

    /// Secondary RPC URL for two-RPC pool WASM-hash cross-check.
    #[arg(long)]
    pub secondary_rpc_url: Option<String>,

    /// Custom maximum staleness threshold in seconds (default 600).
    ///
    /// Set to `0` to force a staleness block.
    #[arg(long)]
    pub max_staleness_secs: Option<u64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Run
// ─────────────────────────────────────────────────────────────────────────────

/// Dispatches the `lend` subcommand.
///
/// Returns `0` on success, `1` on error.
pub async fn run(args: &LendArgs) -> i32 {
    run_with_dependencies(
        args,
        |name| profile_loader::load(name, None),
        init_platform_keyring_store,
    )
    .await
}

/// Testable core of [`run`] with the profile loader and the platform-keyring
/// initialiser injected.
///
/// Production callers use [`run`], which supplies the real profile loader and
/// [`init_platform_keyring_store`]. Tests substitute an in-memory profile and a
/// spy initialiser to assert the keyring store is registered before signer
/// resolution without touching the OS keychain.
async fn run_with_dependencies<LoadProfile, InitKeyring>(
    args: &LendArgs,
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
) -> i32
where
    LoadProfile: Fn(&str) -> Result<Profile, profile_loader::ProfileLoadError>,
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    // ── Load profile ──────────────────────────────────────────────────────────
    let profile = match load_profile(&args.profile) {
        Ok(p) => p,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "profile.load_failed",
                format!("{e}"),
            ));
            return 1;
        }
    };

    // ── Initialise platform keyring store ─────────────────────────────────────
    // The keyring signer loaded before signing requires the process-global
    // default store.  Ordered after the profile load so a missing profile never
    // triggers the store registration.
    if let Err(e) = init_keyring() {
        render_json(&Envelope::<()>::err(&e));
        return 1;
    }

    // ── Resolve network settings ──────────────────────────────────────────────
    let rpc_url = profile.rpc_url.as_str();
    let network_passphrase = profile.network_passphrase.as_str();
    let chain_id = profile.chain_id.caip2_str();
    let is_testnet = chain_id.contains("testnet");

    // ── Construct the BlendRequest ────────────────────────────────────────────
    let request_type = args.op.to_request_type();
    let blend_requests = vec![BlendRequest::new(
        request_type,
        args.asset.clone(),
        args.amount,
    )];

    // ── Build RPCs ────────────────────────────────────────────────────────────
    let primary_rpc = match StellarRpcClient::new(rpc_url) {
        Ok(r) => r,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw("rpc.init_failed", format!("{e}")));
            return 1;
        }
    };
    let secondary_rpc: Option<StellarRpcClient> = match args
        .secondary_rpc_url
        .as_deref()
        .map(StellarRpcClient::new)
        .transpose()
    {
        Ok(s) => s,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "rpc.secondary_init_failed",
                format!("{e}"),
            ));
            return 1;
        }
    };

    let wasm_set: BlendPoolWasmSet = if is_testnet {
        blend_pool_wasm_set_testnet()
    } else {
        blend_pool_wasm_set_pubnet()
    };

    // ── ORDERED TRUST GATE step 1: verify pool WASM hash ─────────────────────
    if let Err(e) =
        verify_blend_pool_wasm(&args.pool, &wasm_set, &primary_rpc, secondary_rpc.as_ref()).await
    {
        render_json(&Envelope::<()>::err_raw(
            "blend.pool_wasm_pin_failed",
            format!("pool WASM hash mismatch: {e}"),
        ));
        return 1;
    }

    // ── ORDERED TRUST GATE step 2: read pool oracle, check allowlist ──────────
    let oracle_address = match read_pool_oracle_address(&args.pool, &primary_rpc).await {
        Ok(addr) => addr,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "blend.oracle_fetch_failed",
                format!("could not read pool oracle: {e}"),
            ));
            return 1;
        }
    };

    let network_label = if is_testnet { "testnet" } else { "pubnet" };
    if !is_oracle_in_allowlist(&oracle_address, network_label) {
        render_json(&Envelope::<()>::err_raw(
            "blend.oracle_not_allowlisted",
            "pool oracle is not in the Reflector allowlist".to_owned(),
        ));
        return 1;
    }

    // ── ORDERED TRUST GATE step 3: oracle staleness ───────────────────────────
    let max_staleness = args
        .max_staleness_secs
        .unwrap_or(DEFAULT_MAX_STALENESS_SECS);

    let timestamps_result = query_oracle_lastprice_timestamps(
        &oracle_address,
        std::slice::from_ref(&args.asset),
        rpc_url,
        network_passphrase,
    )
    .await;

    let staleness_view = match timestamps_result {
        Ok(ts) if !ts.is_empty() => {
            OracleStalenessSnapshot::new(&oracle_address, &ts, max_staleness)
        }
        Ok(_) => Some(OracleStalenessSnapshot::unavailable(
            &oracle_address,
            max_staleness,
        )),
        Err(PoolOracleFetchError::OraclePriceAbsent) => Some(OracleStalenessSnapshot::unavailable(
            &oracle_address,
            max_staleness,
        )),
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "blend.oracle_price_fetch_failed",
                format!("{e}"),
            ));
            return 1;
        }
    };

    let staleness_eval = OracleStalenessEvalExt::evaluate(
        staleness_view
            .as_ref()
            .map(|v| v as &dyn stellar_agent_blend::oracle::OracleStalenessView),
        args.override_oracle_staleness,
    );
    if let Err(reason) = staleness_eval {
        render_json(&Envelope::<()>::err_raw(
            "oracle.staleness_exceeded",
            reason.to_string(),
        ));
        return 1;
    }

    // ── Operator policy evaluation (value-carrying; mirrors the MCP
    // `stellar_blend_lend` twin's `dispatch_gate_with_value` mechanism) ─────
    // Load the operator-signed PolicyEngineV1 (if profile.policy.engine == V1)
    // or a permissive NoopPolicyEngine (if Noop), then evaluate before submit.
    // The legs are built from the SAME `blend_requests` vector later placed
    // into `BlendLendArgs` (single-decode invariant).
    let policy_engine = match build_v1_policy_engine("lend", &profile.policy.engine, &profile) {
        Ok(pe) => pe,
        Err(msg) => {
            // Fail-closed: a configured-but-unbuildable policy refuses the
            // value-moving lend op rather than silently running permissive.
            render_json(&Envelope::<()>::err_raw("policy.engine_unavailable", msg));
            return 1;
        }
    };
    let value_legs = blend_value_legs(&blend_requests, &args.pool);
    // Capture the gate-derived legs as audit records before the descriptor
    // moves into the gate, so the emitted row carries exactly what the gate
    // sized (single-derivation invariant).
    let audit_legs: Vec<stellar_agent_core::audit_log::ValueLegRecord> =
        value_legs.iter().map(Into::into).collect();
    let policy_args = json!({
        "pool_address": args.pool,
        "from_address": args.from,
    });
    if let Err(envelope) = evaluate_value_moving_policy_with_value(
        policy_engine.as_ref(),
        &profile,
        "stellar_blend_lend",
        chain_id,
        &policy_args,
        ValueClass::Value(ValueEffects::new(value_legs)),
        "lend",
    ) {
        render_json(&envelope);
        return 1;
    }

    // ── DeFi dispatch gate (capability-witness seam) ──────────────────────────
    // The verb-registry dispatch_gate produces the SubmitWitness that is the
    // only valid input to BlendLendAdapter::submit.
    let witness = match dispatch_gate("lend", &args.pool) {
        Ok(GateOutcome::Allow(w)) => w,
        Ok(GateOutcome::RequireApproval) => {
            render_json(&Envelope::<()>::err_raw(
                "policy.approval_required",
                require_approval_error(),
            ));
            return 1;
        }
        Err(e) => {
            render_json(&Envelope::<()>::err_raw("blend.gate_error", format!("{e}")));
            return 1;
        }
    };

    // ── Audit pre-flight (fail-closed) ────────────────────────────────────────
    // Proves the profile's audit chain-root key is acquirable BEFORE the
    // signer is loaded (below) or the lend is submitted. Reused (not
    // re-acquired) for `DefiAdapterCtx::audit_writer`.
    let audit_writer =
        match crate::commands::value_audit::require_value_audit_writer(&profile, &args.profile) {
            Ok(w) => w,
            Err(e) => {
                render_json(&Envelope::<()>::err(&e));
                return 1;
            }
        };

    // ── Build preview summary (for the result envelope) ───────────────────────
    let oracle_staleness_secs = staleness_view.as_ref().and_then(|v| {
        use stellar_agent_blend::oracle::OracleStalenessView;
        v.worst_case_age_secs()
    });

    let blend_preview = stellar_agent_blend::preview::build_blend_lend_preview(
        &args.pool,
        &args.from,
        &blend_requests,
        stellar_agent_blend::preview::HfStatus::Unavailable,
        oracle_staleness_secs,
    );
    let preview_text = stellar_agent_blend::preview::preview_summary(&blend_preview);

    // ── Load signer ───────────────────────────────────────────────────────────
    let signer_entry_ref = &profile.mcp_signer_default;
    let expected_g = signer_entry_ref.account.as_str();
    let signer_handle = match signer_from_keyring(signer_entry_ref, expected_g).await {
        Ok(s) => s,
        Err(e) => {
            render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };

    // ── Construct DefiAdapterCtx with full submit context ─────────────────────
    let pool_pin = DefiContractPin::new(
        "blend", "v2", "default", chain_id, &args.pool,
        [0u8; 32], // hash already verified above by verify_blend_pool_wasm
        "ba22b48",
    );

    let timeout = std::time::Duration::from_secs(60);
    let mut ctx = DefiAdapterCtx::new_with_submit_ctx(
        "default",
        &pool_pin,
        &primary_rpc,
        Some(&signer_handle as &(dyn stellar_agent_network::Signer + Send + Sync)),
        Some(network_passphrase),
        Some(chain_id),
        secondary_rpc.as_ref(),
        Some(timeout),
    );
    // Thread the pre-flight-acquired audit writer + gate-derived legs so the
    // adapter emits the ValueActionSubmitted row after a confirmed submit
    // (non-fatal past this point — the pre-flight above is what fails closed).
    ctx.audit_writer = Some(std::sync::Arc::clone(&audit_writer));
    ctx.audit_legs = Some(&audit_legs);
    ctx.audit_tool = Some("stellar_blend_lend");

    // ── Build BlendLendArgs for the adapter ───────────────────────────────────
    let lend_args = BlendLendArgs {
        pool_address: args.pool.clone(),
        from_address: args.from.clone(),
        requests: blend_requests,
        override_oracle_staleness: args.override_oracle_staleness,
    };

    // ── Delegate to BlendLendAdapter::submit (witness consumed inside) ────────
    let adapter = BlendLendAdapter::new();
    let submit_result = adapter
        .submit(
            &lend_args as &(dyn std::any::Any + Send + Sync),
            &ctx,
            witness,
        )
        .await;

    match submit_result {
        Ok(()) => {
            render_json(&Envelope::ok(LendResult {
                summary: preview_text,
                oracle_staleness_secs,
            }));
            0
        }
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "blend.submit_failed",
                e.to_string(),
            ));
            1
        }
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
        reason = "test-only assertions"
    )]

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use stellar_agent_core::error::AuthError;
    use stellar_agent_core::profile::schema::PolicyEngineKind;

    use super::*;
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers::method};

    // ── keyring store initialisation ordering ─────────────────────────────────

    #[tokio::test]
    async fn run_initialises_keyring_store_before_signer_resolution() {
        // The keyring initialiser must be invoked on the run() path, after the
        // profile load and before the signer is resolved from the keyring.
        // Both dependencies are injected, so no OS keychain or on-disk profile
        // is touched and no process-global keyring store is registered — hence
        // this test needs no `#[serial]`.  The injected initialiser returns an
        // error so the run bails at that step, which proves the store
        // initialisation gates the path ahead of signer resolution.
        let profile_loaded = Arc::new(AtomicBool::new(false));
        let init_invoked = Arc::new(AtomicBool::new(false));

        let loaded_writer = Arc::clone(&profile_loaded);
        let loaded_reader = Arc::clone(&profile_loaded);
        let init_writer = Arc::clone(&init_invoked);

        let args = LendArgs {
            profile: "keyring-order-test".to_owned(),
            pool: String::new(),
            from: String::new(),
            op: LendOp::Supply,
            asset: String::new(),
            amount: 0,
            override_oracle_staleness: false,
            secondary_rpc_url: None,
            max_staleness_secs: None,
        };

        let code = run_with_dependencies(
            &args,
            move |_name| {
                loaded_writer.store(true, Ordering::SeqCst);
                Ok(Profile::builder_testnet_named(
                    "keyring-order-test",
                    "stellar-agent-signer",
                    "keyring-order-test",
                    "stellar-agent-nonce",
                    "keyring-order-test",
                )
                .build())
            },
            move || {
                assert!(
                    loaded_reader.load(Ordering::SeqCst),
                    "profile must be loaded before the keyring store is initialised"
                );
                init_writer.store(true, Ordering::SeqCst);
                Err(WalletError::Auth(AuthError::KeyringNotFound {
                    name: "keyring-order-test-sentinel".to_owned(),
                }))
            },
        )
        .await;

        assert!(
            init_invoked.load(Ordering::SeqCst),
            "run must initialise the keyring store before resolving the signer"
        );
        assert_eq!(
            code, 1,
            "run must surface the keyring init failure instead of reaching signer resolution"
        );
    }

    // ── Audit pre-flight (fail-closed) after the ordered trust gate ──────────
    //
    // Unlike `trustline`'s zero-RPC ordering test, `lend`'s audit pre-flight
    // (module doc: "Audit pre-flight (fail-closed)") runs AFTER the ordered
    // trust gate's three RPC round trips (pool WASM-hash pin, pool oracle-address
    // read, oracle `lastprice` staleness query — see the module doc's "Ordered
    // trust gate" section and the call sequence in `run_with_dependencies`
    // above), so a `server.received_requests().is_empty()` assertion would be
    // structurally wrong here (see cycle-2 brief item B). These helpers mock the
    // ordered trust gate to a genuine PASS so the run reaches the real
    // production pre-flight call site instead of refusing earlier for an
    // unrelated reason.

    /// Builds the base64 XDR `(key, entry)` pair for a Blend pool's contract
    /// instance ledger entry, carrying a pinned WASM executable hash and a
    /// `PoolConfig.oracle` field — the SAME single instance entry both
    /// `verify_blend_pool_wasm` (via `fetch_contract_wasm_hash`) and
    /// `read_pool_oracle_address` decode, per their `getLedgerEntries` call
    /// against `LedgerKeyContractInstance`.
    ///
    /// # ABI provenance
    ///
    /// `PoolConfig.oracle: Address` at instance-storage key `Symbol("Config")`,
    /// per `stellar_agent_blend::oracle_fetch::read_pool_oracle_address`'s own
    /// ABI-provenance rustdoc; only the `oracle` field is populated since
    /// `extract_oracle_from_pool_config_scval` searches by key name and never
    /// consumes any other `PoolConfig` field.
    fn blend_pool_instance_key_and_entry_xdr(
        pool_address: &str,
        wasm_hash: [u8; 32],
        oracle_address: &str,
    ) -> (String, String) {
        use stellar_xdr::{
            ContractDataDurability, ContractDataEntry, ContractExecutable, ContractId,
            ExtensionPoint, Hash, LedgerEntryData, LedgerKey, LedgerKeyContractData, Limits,
            ScAddress, ScContractInstance, ScMap, ScMapEntry, ScSymbol, ScVal, StringM, WriteXdr,
        };

        let pool =
            stellar_strkey::Contract::from_string(pool_address).expect("valid pool C-strkey");
        let sc_addr = ScAddress::Contract(ContractId(Hash(pool.0)));

        let oracle =
            stellar_strkey::Contract::from_string(oracle_address).expect("valid oracle C-strkey");
        let oracle_sc_addr = ScAddress::Contract(ContractId(Hash(oracle.0)));

        let oracle_sym: StringM<32> = "oracle".try_into().expect("'oracle' fits ScSymbol");
        let config_sym: StringM<32> = "Config".try_into().expect("'Config' fits ScSymbol");

        let pool_config_map = ScMap(
            vec![ScMapEntry {
                key: ScVal::Symbol(ScSymbol(oracle_sym)),
                val: ScVal::Address(oracle_sc_addr),
            }]
            .try_into()
            .expect("single-entry ScMap fits VecM"),
        );

        let storage = ScMap(
            vec![ScMapEntry {
                key: ScVal::Symbol(ScSymbol(config_sym)),
                val: ScVal::Map(Some(pool_config_map)),
            }]
            .try_into()
            .expect("single-entry ScMap fits VecM"),
        );

        let instance = ScContractInstance {
            executable: ContractExecutable::Wasm(Hash(wasm_hash)),
            storage: Some(storage),
        };

        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: sc_addr.clone(),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        });
        let entry_data = LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: sc_addr,
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val: ScVal::ContractInstance(instance),
        });

        let key_b64 = key.to_xdr_base64(Limits::none()).expect("key XDR encode");
        let val_b64 = entry_data
            .to_xdr_base64(Limits::none())
            .expect("entry XDR encode");
        (key_b64, val_b64)
    }

    /// Builds the base64 XDR of a Reflector `Option<PriceData>` `ScVal` result
    /// (the `Some` case) for a `simulateTransaction` `results[0].xdr` field.
    ///
    /// # ABI provenance
    ///
    /// Field order alphabetical (`price` < `timestamp`), `price: i128` encoded
    /// as `ScVal::I128(Int128Parts{hi,lo})`, per
    /// `stellar_agent_defi::reflector::decode_price_data`'s ABI-provenance
    /// rustdoc.
    fn reflector_price_data_scval_xdr(price: i128, timestamp: u64) -> String {
        use stellar_xdr::{
            Int128Parts, Limits, ScMap, ScMapEntry, ScSymbol, ScVal, StringM, WriteXdr,
        };

        let price_sym: StringM<32> = "price".try_into().expect("'price' fits ScSymbol");
        let timestamp_sym: StringM<32> = "timestamp".try_into().expect("'timestamp' fits ScSymbol");

        let hi = (price >> 64) as i64;
        let lo = (price & i128::from(u64::MAX)) as u64;

        let map = ScMap(
            vec![
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol(price_sym)),
                    val: ScVal::I128(Int128Parts { hi, lo }),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol(timestamp_sym)),
                    val: ScVal::U64(timestamp),
                },
            ]
            .try_into()
            .expect("two-entry ScMap fits VecM"),
        );

        ScVal::Map(Some(map))
            .to_xdr_base64(Limits::none())
            .expect("PriceData ScVal XDR encode")
    }

    /// Answers `getLedgerEntries` (the pool instance, reused by both the
    /// WASM-pin check and the oracle-address read) and `simulateTransaction`
    /// (the Reflector `lastprice` query) with fixed successful responses, so
    /// the ordered trust gate completes and `run_with_dependencies` reaches
    /// the audit pre-flight.
    struct LendTrustGateResponder {
        pool_entry_xdr: String,
        price_scval_xdr: String,
    }

    #[async_trait::async_trait]
    impl Respond for LendTrustGateResponder {
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
                "getLedgerEntries" => serde_json::json!({
                    "entries": [{
                        "key": "unused-by-the-decoder",
                        "xdr": self.pool_entry_xdr,
                        "lastModifiedLedgerSeq": 1000
                    }],
                    "latestLedger": 1001
                }),
                "simulateTransaction" => serde_json::json!({
                    "latestLedger": 1001,
                    "minResourceFee": "100",
                    "results": [{"auth": [], "xdr": self.price_scval_xdr}]
                }),
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

    /// Proves the audit pre-flight is still wired into `run_with_dependencies`'s
    /// production path AFTER the ordered trust gate — not merely unit-tested in
    /// isolation. Mocks the ordered gate to a genuine PASS (a matching pinned
    /// WASM hash, an allowlisted oracle, a fresh positive price) so the run
    /// reaches the real pre-flight call site and refuses there
    /// (`audit.chain_key_unavailable`) because the profile's audit chain-root
    /// key was never minted at its unique keyring coordinate. The exact
    /// `received_requests` count of 3 (two `getLedgerEntries` — WASM-pin,
    /// oracle-address — plus one `simulateTransaction` — oracle `lastprice`) is
    /// what makes this discriminating: fewer requests would mean the gate was
    /// short-circuited or bypassed before completing; more would mean an
    /// unexpected extra round trip crept into the ordered gate.
    #[tokio::test]
    #[serial_test::serial]
    async fn run_refuses_after_ordered_trust_gate_when_audit_key_unminted() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");

        let pool_c = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        let oracle_c = stellar_agent_blend::pins::REFLECTOR_ORACLE_ALLOWLIST_TESTNET[0];
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_secs();

        let (_pool_key_xdr, pool_entry_xdr) = blend_pool_instance_key_and_entry_xdr(
            pool_c,
            stellar_agent_blend::pins::BLEND_V2_POOL_WASM_HASH_TESTNET,
            oracle_c,
        );
        let price_scval_xdr = reflector_price_data_scval_xdr(10_000_000, now_secs);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(LendTrustGateResponder {
                pool_entry_xdr,
                price_scval_xdr,
            })
            .mount(&server)
            .await;
        let rpc_url = server.uri();

        let args = LendArgs {
            profile: "lend-audit-preflight-test".to_owned(),
            pool: pool_c.to_owned(),
            from: pool_c.to_owned(),
            op: LendOp::Supply,
            asset: pool_c.to_owned(),
            amount: 1_000_000,
            override_oracle_staleness: false,
            secondary_rpc_url: None,
            max_staleness_secs: None,
        };

        let code = run_with_dependencies(
            &args,
            move |_name| {
                let mut profile = Profile::builder_testnet_named(
                    "lend-audit-preflight-test",
                    "stellar-agent-signer",
                    "lend-audit-preflight-test",
                    "stellar-agent-nonce",
                    "lend-audit-preflight-test",
                )
                .policy_engine(PolicyEngineKind::Noop)
                .build();
                profile.rpc_url = rpc_url.clone();
                Ok(profile)
            },
            || Ok(()),
        )
        .await;

        assert_eq!(
            code, 1,
            "run must refuse when the audit chain-root key is unminted, even \
             after the ordered trust gate passes"
        );
        let requests = server
            .received_requests()
            .await
            .expect("request recording is enabled by default");
        assert_eq!(
            requests.len(),
            3,
            "the ordered trust gate must complete (pool WASM-pin + oracle-address \
             read via getLedgerEntries, oracle lastprice via simulateTransaction) \
             BEFORE the audit pre-flight refuses — a different count means the \
             gate was bypassed, short-circuited, or the pre-flight fired at the \
             wrong point"
        );
    }
}
