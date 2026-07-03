//! DeFindex vault instance-storage read primitives.
//!
//! # What this module does
//!
//! Provides:
//! - [`read_vault_upgradable_flag`] — reads `DataKey::Upgradable` from the
//!   contract instance via `getLedgerEntries` (step 2 of the ordered gate).
//! - [`read_vault_assets`] — reads the asset+strategy set from the contract
//!   instance via `getLedgerEntries` (step 4 of the ordered gate); shared by
//!   MCP and CLI dispatch sites so Blend-strategy detection and asset-count
//!   validation are NOT duplicated.
//! - [`read_vault_share_balance`] — reads the vault share (dfToken) balance
//!   for a given address via a read-only `simulate_transaction` of
//!   `balance(id: Address) -> i128` (SEP-41; the DeFindex vault IS the dfToken
//!   contract).
//!
//! All functions MUST be called ONLY after [`crate::pins::verify_defindex_vault_wasm`] passes.
//!
//! # `DataKey::Upgradable` encoding
//!
//! `DataKey` is a `#[contracttype]` enum.
//! The `Upgradable` variant is a unit variant.  Per the soroban-sdk-macros
//! 22.0.3 enum derive
//! (`https://github.com/stellar/rs-soroban-sdk/blob/v22.0.3/soroban-sdk-macros/src/derive_enum.rs`),
//! a unit-variant `into_xdr` produces:
//!
//! ```text
//! let symbol = ScSymbol(case_name.try_into()?);
//! let val = ScVal::Symbol(symbol);
//! (val,).try_into()?              // → ScVec([Symbol("Upgradable")])
//! → ScVal::Vec(Some(ScVec([Symbol("Upgradable")])))
//! ```
//!
//! Confirmed stable across soroban-sdk-macros 22.0.3 and 25.3.1.  The
//! deployed DeFindex vault contracts use soroban-sdk 22.0.3.
//!
//! The full `getLedgerEntries` key is:
//! ```text
//! LedgerKey::ContractData {
//!     contract: ScAddress::Contract(ContractId(Hash([...vault bytes...]))),
//!     key: ScVal::LedgerKeyContractInstance,
//!     durability: ContractDataDurability::Persistent,
//! }
//! ```
//! Note: all instance-stored keys (`DataKey::Upgradable`, `RolesDataKey::*`,
//! `DataKey::TotalAssets`, `DataKey::AssetStrategySet(i)`) are stored in the
//! CONTRACT INSTANCE entry.  The instance entry is fetched with
//! `LedgerKeyContractInstance` and the individual keys are found by scanning
//! the `.storage` map of the returned `ScVal::ContractInstance`.
//!
//! # Fail-safe: absent = upgradable:true
//!
//! If the `Upgradable` key is absent from instance storage, the function
//! returns `true` — mirroring the contract's own `.unwrap_or(true)`.
//! Absent = upgradable = fail toward refusal.
//!
//! # `read_vault_share_balance` simulate path
//!
//! [`read_vault_share_balance`] is the ONLY function in this module that uses
//! `simulate_transaction`.  It invokes `balance(id: Address) -> i128` on the
//! vault contract (the DeFindex vault IS its own dfToken/SEP-41 contract).
//! All other functions in this module use `getLedgerEntries`.

use stellar_agent_network::StellarRpcClient;
use stellar_agent_xdr_limits::untrusted_decode_limits;
use stellar_strkey::Contract;
use stellar_xdr::{
    ContractDataDurability, Hash, LedgerEntryData, LedgerKey, LedgerKeyContractData, ReadXdr,
    ScAddress, ScSymbol, ScVal, ScVec, StringM, VecM,
};

use crate::abi::{WalletAssetStrategySet, WalletStrategy};

// ─────────────────────────────────────────────────────────────────────────────
// VaultStorageFetchError
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of assets a DeFindex vault may report.
///
/// An untrusted `TotalAssets` value of `u32::MAX` would trigger a multi-GB
/// `Vec::with_capacity` allocation.  This constant bounds that to a realistic
/// maximum; a vault realistically has a handful of assets.
pub const MAX_VAULT_ASSETS: u32 = 16;

/// Checks that `total` is within the `MAX_VAULT_ASSETS` bound.
///
/// Returns `Ok(())` when `total <= MAX_VAULT_ASSETS`, and
/// `Err(VaultStorageFetchError::TooManyAssets)` otherwise.
///
/// # Errors
///
/// Returns [`VaultStorageFetchError::TooManyAssets`] when `total > MAX_VAULT_ASSETS`.
pub fn check_asset_count(total: u32) -> Result<(), VaultStorageFetchError> {
    if total > MAX_VAULT_ASSETS {
        return Err(VaultStorageFetchError::TooManyAssets {
            count: total,
            max: MAX_VAULT_ASSETS,
        });
    }
    Ok(())
}

/// Error returned by vault storage read operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VaultStorageFetchError {
    /// The vault address is not a valid Stellar C-strkey.
    #[error("invalid vault address: {reason}")]
    InvalidAddress {
        /// Non-sensitive reason.
        reason: String,
    },
    /// The `getLedgerEntries` RPC call failed.
    #[error("RPC getLedgerEntries failed: {reason}")]
    LedgerFetchFailed {
        /// Non-sensitive reason.
        reason: String,
    },
    /// The vault contract instance entry was not found on the ledger.
    #[error("vault contract instance not found on ledger")]
    InstanceNotFound,
    /// An XDR encoding or decoding operation failed.
    #[error("XDR encode/decode error: {reason}")]
    XdrError {
        /// Non-sensitive reason.
        reason: String,
    },
    /// The `TotalAssets` key is absent from instance storage (vault not initialized).
    #[error("vault DataKey::TotalAssets absent from instance storage (vault not initialized)")]
    TotalAssetsAbsent,
    /// The on-chain `TotalAssets` count exceeds the safety bound `MAX_VAULT_ASSETS`.
    ///
    /// A forged or corrupt `TotalAssets = u32::MAX` would otherwise trigger a
    /// multi-GB `Vec::with_capacity` OOM.
    #[error(
        "vault reports {count} assets which exceeds the safety maximum of {max}; \
         refusing to allocate (possible corrupt/hostile storage)"
    )]
    TooManyAssets {
        /// The on-chain value.
        count: u32,
        /// The configured maximum (`MAX_VAULT_ASSETS`).
        max: u32,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// read_vault_upgradable_flag
// ─────────────────────────────────────────────────────────────────────────────

/// Reads the `DataKey::Upgradable` flag from the vault's instance storage.
///
/// Returns `true` when the vault is upgradable (either explicitly set or
/// absent — the contract's `.unwrap_or(true)` means "absent = upgradable").
///
/// This is **step 2** of the ordered trust gate.  The dispatch site calls
/// this ONLY after `verify_defindex_vault_wasm` passes.
///
/// # Algorithm
///
/// 1. Build a `LedgerKey::ContractData` with `ScVal::LedgerKeyContractInstance`.
/// 2. Call `getLedgerEntries` via the primary RPC (returns base64 XDR entries).
/// 3. Decode the returned `LedgerEntryData::ContractData`.
/// 4. Extract the `ContractInstance.storage` map.
/// 5. Find entry with key `ScVal::Vec([Symbol("Upgradable")])`.
/// 6. If found: decode as `ScVal::Bool(b)`.
/// 7. If absent: return `true` (fail-safe, mirroring the contract's `.unwrap_or(true)`).
///
/// # Errors
///
/// Returns [`VaultStorageFetchError`] on any RPC or XDR failure.
pub async fn read_vault_upgradable_flag(
    vault_address: &str,
    primary_rpc: &StellarRpcClient,
) -> Result<bool, VaultStorageFetchError> {
    // ── 1. Build the instance storage ledger key ─────────────────────────────
    let instance_key = build_instance_ledger_key(vault_address)?;

    // ── 2. Call getLedgerEntries (direct StellarRpcClient call) ──────────────
    // Uses the shared `rpc.get_ledger_entries(&[key])` pattern.
    let response = primary_rpc
        .get_ledger_entries(&[instance_key])
        .await
        .map_err(|e| VaultStorageFetchError::LedgerFetchFailed {
            reason: format!("{e}"),
        })?;

    let entries = response.entries.unwrap_or_default();
    if entries.is_empty() {
        return Err(VaultStorageFetchError::InstanceNotFound);
    }

    // ── 3. Decode the first entry as LedgerEntryData ─────────────────────────
    // Bound depth + length: the RPC server is untrusted (user-configured or
    // MITM-tampered). `untrusted_decode_limits` bounds both depth (500) and
    // length (input byte count), refusing a depth-bomb DoS.
    let entry_data = LedgerEntryData::from_xdr_base64(
        &entries[0].xdr,
        untrusted_decode_limits(entries[0].xdr.len()),
    )
    .map_err(|e| VaultStorageFetchError::XdrError {
        reason: format!("LedgerEntryData decode: {e}"),
    })?;

    // ── 4. Extract ContractInstance from the ContractData entry ──────────────
    let contract_data = match entry_data {
        LedgerEntryData::ContractData(cd) => cd,
        _ => {
            return Err(VaultStorageFetchError::XdrError {
                reason: "expected ContractData entry".to_owned(),
            });
        }
    };

    let instance = match contract_data.val {
        ScVal::ContractInstance(ci) => ci,
        _ => {
            return Err(VaultStorageFetchError::XdrError {
                reason: "expected ScVal::ContractInstance in instance entry".to_owned(),
            });
        }
    };

    // ── 5. Find DataKey::Upgradable in the instance storage map ─────────────
    let upgradable_key = build_upgradable_scval_key()?;

    let storage_map = match instance.storage {
        Some(map) => map,
        None => {
            // No storage map → key is absent → upgradable:true (fail-safe).
            return Ok(true);
        }
    };

    for entry in storage_map.0.iter() {
        if entry.key == upgradable_key {
            return match &entry.val {
                ScVal::Bool(b) => Ok(*b),
                other => Err(VaultStorageFetchError::XdrError {
                    reason: format!("DataKey::Upgradable value is not ScVal::Bool: {other:?}"),
                }),
            };
        }
    }

    // Key absent from map → upgradable:true (fail-safe).
    Ok(true)
}

// ─────────────────────────────────────────────────────────────────────────────
// read_vault_assets
// ─────────────────────────────────────────────────────────────────────────────

/// Reads the vault's asset+strategy set from contract instance storage.
///
/// Returns `Vec<WalletAssetStrategySet>` with `is_blend_strategy = false` on
/// every strategy.  Blend-strategy detection (WASM-hash match) is performed
/// by the caller after this function returns, to avoid coupling a network call
/// to storage decoding.
///
/// This is **step 4** of the ordered trust gate.  Called ONLY after steps 1-3
/// pass (WASM-pin, upgradable-flag, roles).
///
/// # Algorithm
///
/// All assets are stored in contract **instance** storage.  A single
/// `getLedgerEntries` call (keyed by `LedgerKeyContractInstance`) fetches the
/// full instance storage map.  The function then locates `DataKey::TotalAssets`
/// (a `ScVal::U32`) and iterates `DataKey::AssetStrategySet(i)` for each index
/// `i` in `0..total`, decoding each value as an `AssetStrategySet` ScMap.
///
/// `DataKey::TotalAssets` encodes as `ScVal::Vec([Symbol("TotalAssets")])`.
/// `DataKey::AssetStrategySet(i)` encodes as
/// `ScVal::Vec([Symbol("AssetStrategySet"), U32(i)])` per the
/// soroban-sdk-macros 22.0.3 1-tuple-variant enum encoding.
///
/// # Safety bound
///
/// The `TotalAssets` count is untrusted (read from a user-configured RPC server).
/// A forged value of `u32::MAX` would trigger a multi-GB `Vec::with_capacity`
/// allocation.  The count is checked against [`MAX_VAULT_ASSETS`] before
/// allocating; values above the bound return [`VaultStorageFetchError::TooManyAssets`].
///
/// # `AssetStrategySet` XDR encoding
///
/// `AssetStrategySet` is a `#[contracttype]` struct with fields sorted
/// alphabetically by the soroban-sdk-macros 22.0.3 struct derive:
///
/// ```text
/// ScMap([
///   { key: Symbol("address"),    val: ScVal::Address(...) },
///   { key: Symbol("strategies"), val: ScVal::Vec([...Strategy ScMaps...]) },
/// ])
/// ```
///
/// `Strategy` likewise encodes with fields sorted alphabetically:
/// `address`, `name`, `paused`.
///
/// # Errors
///
/// Returns [`VaultStorageFetchError`] on RPC failure, missing `TotalAssets`,
/// oversized asset count, or XDR decoding errors.
pub async fn read_vault_assets(
    vault_address: &str,
    primary_rpc: &StellarRpcClient,
) -> Result<Vec<WalletAssetStrategySet>, VaultStorageFetchError> {
    // ── 1. Build instance storage ledger key ─────────────────────────────────
    let instance_key = build_instance_ledger_key(vault_address)?;

    // ── 2. Call getLedgerEntries ─────────────────────────────────────────────
    let response = primary_rpc
        .get_ledger_entries(&[instance_key])
        .await
        .map_err(|e| VaultStorageFetchError::LedgerFetchFailed {
            reason: format!("{e}"),
        })?;

    let entries = response.entries.unwrap_or_default();
    if entries.is_empty() {
        return Err(VaultStorageFetchError::InstanceNotFound);
    }

    // ── 3. Decode LedgerEntryData ────────────────────────────────────────────
    // Bound depth + length: the RPC server is untrusted; `untrusted_decode_limits`
    // bounds depth (500) and length (input byte count), refusing a depth-bomb DoS.
    let entry_data = LedgerEntryData::from_xdr_base64(
        &entries[0].xdr,
        untrusted_decode_limits(entries[0].xdr.len()),
    )
    .map_err(|e| VaultStorageFetchError::XdrError {
        reason: format!("LedgerEntryData decode: {e}"),
    })?;

    let contract_data = match entry_data {
        LedgerEntryData::ContractData(cd) => cd,
        _ => {
            return Err(VaultStorageFetchError::XdrError {
                reason: "expected ContractData entry".to_owned(),
            });
        }
    };

    let instance = match contract_data.val {
        ScVal::ContractInstance(ci) => ci,
        _ => {
            return Err(VaultStorageFetchError::XdrError {
                reason: "expected ScVal::ContractInstance".to_owned(),
            });
        }
    };

    let storage_map = match instance.storage {
        Some(map) => map,
        None => return Err(VaultStorageFetchError::TotalAssetsAbsent),
    };

    // ── 4. Read TotalAssets count ────────────────────────────────────────────
    let total_assets_key = build_unit_variant_scval_key("TotalAssets")?;
    let mut total: u32 = 0;
    let mut found_total = false;
    for entry in storage_map.0.iter() {
        if entry.key == total_assets_key {
            match &entry.val {
                ScVal::U32(n) => {
                    total = *n;
                    found_total = true;
                }
                other => {
                    return Err(VaultStorageFetchError::XdrError {
                        reason: format!("DataKey::TotalAssets value is not ScVal::U32: {other:?}"),
                    });
                }
            }
            break;
        }
    }
    if !found_total {
        return Err(VaultStorageFetchError::TotalAssetsAbsent);
    }

    // ── 5. Clamp total against DoS bound, then decode each AssetStrategySet ────
    // `total` is from an untrusted RPC response; u32::MAX would trigger a
    // multi-GB Vec::with_capacity OOM before any bounds check in the loop.
    check_asset_count(total)?;
    let mut assets: Vec<WalletAssetStrategySet> = Vec::with_capacity(total as usize);
    for i in 0..total {
        let asset_key = build_asset_strategy_set_key(i)?;
        let mut found = false;
        for entry in storage_map.0.iter() {
            if entry.key == asset_key {
                let wallet_asset = decode_asset_strategy_set_scval(&entry.val)?;
                assets.push(wallet_asset);
                found = true;
                break;
            }
        }
        if !found {
            return Err(VaultStorageFetchError::XdrError {
                reason: format!(
                    "DataKey::AssetStrategySet({i}) absent from instance storage (TotalAssets says {total})"
                ),
            });
        }
    }

    Ok(assets)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn build_instance_ledger_key(vault_address: &str) -> Result<LedgerKey, VaultStorageFetchError> {
    let contract = Contract::from_string(vault_address).map_err(|e| {
        VaultStorageFetchError::InvalidAddress {
            reason: format!("{e}"),
        }
    })?;
    Ok(LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(stellar_xdr::ContractId(Hash(contract.0))),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    }))
}

/// Builds the `ScVal::Vec([Symbol("Upgradable")])` key for the `DataKey::Upgradable`
/// unit variant of the `#[contracttype]` enum.
///
/// Encoding per the soroban-sdk-macros 22.0.3 enum derive:
/// unit-variant `into_xdr` → `ScVal::Symbol(case_name)` wrapped as
/// `(val,).try_into()` → `ScVec([Symbol("Upgradable")])` → `ScVal::Vec(...)`.
fn build_upgradable_scval_key() -> Result<ScVal, VaultStorageFetchError> {
    build_unit_variant_scval_key("Upgradable")
}

/// Builds the `ScVal::Vec([Symbol(variant_name)])` key for any unit variant
/// of a `#[contracttype]` enum stored in instance storage.
///
/// # Errors
///
/// Returns `VaultStorageFetchError::XdrError` if `variant_name` exceeds
/// the `ScSymbol` 32-byte limit.
pub fn build_unit_variant_scval_key(variant_name: &str) -> Result<ScVal, VaultStorageFetchError> {
    let sym_str: StringM<32> =
        variant_name
            .try_into()
            .map_err(|_| VaultStorageFetchError::XdrError {
                reason: format!("variant name '{variant_name}' too long for ScSymbol"),
            })?;
    let sym = ScSymbol(sym_str);
    let vec_m: VecM<ScVal> =
        vec![ScVal::Symbol(sym)]
            .try_into()
            .map_err(|_| VaultStorageFetchError::XdrError {
                reason: "VecM overflow building unit-variant key".to_owned(),
            })?;
    Ok(ScVal::Vec(Some(ScVec(vec_m))))
}

/// Builds the `ScVal::Vec([Symbol("AssetStrategySet"), U32(index)])` key for
/// the `DataKey::AssetStrategySet(u32)` 1-tuple variant.
///
/// Per the soroban-sdk-macros 22.0.3 enum derive, a 1-tuple variant encodes
/// as `ScVec([Symbol(name), value])` → `ScVal::Vec(...)`.
/// The `u32` field encodes as `ScVal::U32(index)`.
///
/// # Errors
///
/// Returns `VaultStorageFetchError::XdrError` on VecM overflow (unreachable
/// in practice — 2-element vec well within limits).
fn build_asset_strategy_set_key(index: u32) -> Result<ScVal, VaultStorageFetchError> {
    let sym_str: StringM<32> =
        "AssetStrategySet"
            .try_into()
            .map_err(|_| VaultStorageFetchError::XdrError {
                reason: "AssetStrategySet symbol too long".to_owned(),
            })?;
    let sym = ScSymbol(sym_str);
    let vec_m: VecM<ScVal> = vec![ScVal::Symbol(sym), ScVal::U32(index)]
        .try_into()
        .map_err(|_| VaultStorageFetchError::XdrError {
            reason: "VecM overflow building AssetStrategySet key".to_owned(),
        })?;
    Ok(ScVal::Vec(Some(ScVec(vec_m))))
}

/// Decodes an `AssetStrategySet` ScMap value from instance storage into
/// `WalletAssetStrategySet`.
///
/// # `AssetStrategySet` XDR layout (alphabetically sorted by field name)
///
/// ```text
/// ScMap([
///   { key: Symbol("address"),    val: ScVal::Address(...) },
///   { key: Symbol("strategies"), val: ScVal::Vec([...]) },
/// ])
/// ```
///
/// Per the soroban-sdk-macros 22.0.3 struct derive, fields in a
/// `#[contracttype]` struct are sorted alphabetically on encode/decode.
///
/// All `WalletStrategy` entries have `is_blend_strategy = false`.
/// The caller sets this field via WASM-hash lookup after this function returns.
///
/// # Errors
///
/// Returns `VaultStorageFetchError::XdrError` when the ScVal does not match
/// the expected `AssetStrategySet` layout.
fn decode_asset_strategy_set_scval(
    val: &ScVal,
) -> Result<WalletAssetStrategySet, VaultStorageFetchError> {
    let map = match val {
        ScVal::Map(Some(m)) => m,
        other => {
            return Err(VaultStorageFetchError::XdrError {
                reason: format!("AssetStrategySet: expected ScMap; got {other:?}"),
            });
        }
    };

    let address = find_address_in_scmap(map, "address")?;

    // Decode strategies: Vec<Strategy>
    let strategies_key = build_sym_scval("strategies")?;
    let strategies_val = map.0.iter().find(|e| e.key == strategies_key);
    let strategies_val = strategies_val.ok_or_else(|| VaultStorageFetchError::XdrError {
        reason: "AssetStrategySet: 'strategies' key absent".to_owned(),
    })?;

    let strategy_vec = match &strategies_val.val {
        ScVal::Vec(Some(v)) => v,
        ScVal::Vec(None) => {
            // Empty strategies vector.
            return Ok(WalletAssetStrategySet {
                address,
                strategies: Vec::new(),
            });
        }
        other => {
            return Err(VaultStorageFetchError::XdrError {
                reason: format!("AssetStrategySet: 'strategies' is not ScVec; got {other:?}"),
            });
        }
    };

    let strategies: Result<Vec<WalletStrategy>, VaultStorageFetchError> =
        strategy_vec.0.iter().map(decode_strategy_scval).collect();

    Ok(WalletAssetStrategySet {
        address,
        strategies: strategies?,
    })
}

/// Decodes a single `Strategy` ScMap entry.
///
/// # `Strategy` XDR layout (alphabetically sorted)
///
/// ```text
/// ScMap([
///   { key: Symbol("address"), val: ScVal::Address(...) },
///   { key: Symbol("name"),    val: ScVal::String("...") },
///   { key: Symbol("paused"),  val: ScVal::Bool(b) },
/// ])
/// ```
///
/// # Errors
///
/// Returns `VaultStorageFetchError::XdrError` on layout mismatch.
fn decode_strategy_scval(val: &ScVal) -> Result<WalletStrategy, VaultStorageFetchError> {
    let map = match val {
        ScVal::Map(Some(m)) => m,
        other => {
            return Err(VaultStorageFetchError::XdrError {
                reason: format!("Strategy: expected ScMap; got {other:?}"),
            });
        }
    };

    let address = find_address_in_scmap(map, "address")?;

    // Decode name: Soroban String encodes as ScVal::String.
    let name_key = build_sym_scval("name")?;
    let name_entry = map.0.iter().find(|e| e.key == name_key);
    let name = match name_entry.map(|e| &e.val) {
        Some(ScVal::String(s)) => String::from_utf8_lossy(&s.0).into_owned(),
        Some(other) => {
            return Err(VaultStorageFetchError::XdrError {
                reason: format!("Strategy: 'name' is not ScVal::String; got {other:?}"),
            });
        }
        None => String::new(),
    };

    // Decode paused: bool.
    let paused_key = build_sym_scval("paused")?;
    let paused_entry = map.0.iter().find(|e| e.key == paused_key);
    let paused = match paused_entry.map(|e| &e.val) {
        Some(ScVal::Bool(b)) => *b,
        Some(other) => {
            return Err(VaultStorageFetchError::XdrError {
                reason: format!("Strategy: 'paused' is not ScVal::Bool; got {other:?}"),
            });
        }
        // Absent = not paused (safe default — strategy is active).
        None => false,
    };

    Ok(WalletStrategy {
        address,
        name,
        paused,
        is_blend_strategy: false,
    })
}

/// Looks up a `ScVal::Address` by `Symbol(key_name)` in a `ScMap`.
///
/// # Errors
///
/// Returns `XdrError` when the key is absent or the value is not an address.
fn find_address_in_scmap(
    map: &stellar_xdr::ScMap,
    key_name: &str,
) -> Result<String, VaultStorageFetchError> {
    let key = build_sym_scval(key_name)?;
    let entry = map.0.iter().find(|e| e.key == key);
    match entry.map(|e| &e.val) {
        Some(ScVal::Address(sc_addr)) => sc_address_to_strkey(sc_addr),
        Some(other) => Err(VaultStorageFetchError::XdrError {
            reason: format!("'{key_name}' is not ScVal::Address; got {other:?}"),
        }),
        None => Err(VaultStorageFetchError::XdrError {
            reason: format!("'{key_name}' absent from ScMap"),
        }),
    }
}

/// Builds a `ScVal::Symbol(name)` for use as a ScMap key.
fn build_sym_scval(name: &str) -> Result<ScVal, VaultStorageFetchError> {
    let sym_str: StringM<32> = name
        .try_into()
        .map_err(|_| VaultStorageFetchError::XdrError {
            reason: format!("symbol '{name}' too long for ScSymbol"),
        })?;
    Ok(ScVal::Symbol(ScSymbol(sym_str)))
}

/// Converts an `ScAddress` to a Stellar strkey string.
///
/// Used by both `storage.rs` (asset decoding) and `roles.rs` (role address
/// decoding).
pub(crate) fn sc_address_to_strkey(sc_addr: &ScAddress) -> Result<String, VaultStorageFetchError> {
    use stellar_xdr::PublicKey;
    match sc_addr {
        ScAddress::Account(account_id) => {
            let bytes = match &account_id.0 {
                PublicKey::PublicKeyTypeEd25519(key) => key.0,
            };
            let pk = stellar_strkey::ed25519::PublicKey(bytes);
            Ok(format!("{}", stellar_strkey::Strkey::PublicKeyEd25519(pk)))
        }
        ScAddress::Contract(contract_id) => {
            let c = stellar_strkey::Contract(contract_id.0.0);
            Ok(format!("{}", stellar_strkey::Strkey::Contract(c)))
        }
        other => Err(VaultStorageFetchError::XdrError {
            reason: format!("unexpected ScAddress variant: {other:?}"),
        }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VaultShareBalanceFetchError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned by [`read_vault_share_balance`].
///
/// All variants carry non-sensitive diagnostic text; no full strkeys are
/// included in `Display` output.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VaultShareBalanceFetchError {
    /// The vault or holder address is not a valid Stellar C-strkey or G-strkey.
    #[error("invalid address: {reason}")]
    InvalidAddress {
        /// Non-sensitive reason.
        reason: String,
    },
    /// The `simulate_transaction` RPC call failed.
    #[error("simulate_transaction failed: {reason}")]
    SimulateFailed {
        /// Non-sensitive reason.
        reason: String,
    },
    /// The simulate returned a contract error (e.g. account not found = balance 0).
    #[error("simulate returned error: {reason}")]
    SimulateError {
        /// Non-sensitive reason.
        reason: String,
    },
    /// The return value could not be decoded as `i128`.
    #[error("balance decode failed: {reason}")]
    DecodeFailed {
        /// Non-sensitive reason.
        reason: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// read_vault_share_balance
// ─────────────────────────────────────────────────────────────────────────────

/// Reads the dfToken (vault share) balance for `holder_address` from the vault
/// contract via a read-only `simulate_transaction`.
///
/// The DeFindex vault contract IS the dfToken/SEP-41 share contract — it
/// implements `token::Interface::balance(id: Address) -> i128` directly
/// (DeFindex vault contract).
/// Calling `balance(id)` on the vault contract address returns the share
/// balance for `id`.
///
/// # ABI provenance
///
/// `fn balance(e: Env, id: Address) -> i128` from the DeFindex vault token
/// contract (DeFindex vault, GPL-3.0, interface-bind only).
///
/// Argument encoding: single `ScVal::Address(ScAddress::Contract(...))` for
/// C-strkey holders; `ScVal::Address(ScAddress::Account(...))` for G-strkey.
///
/// Return type `i128` encodes as `ScVal::I128(stellar_xdr::Int128Parts { hi, lo })`;
/// reconstruction follows the standard `Int128Parts` `hi`/`lo` recombination.
///
/// An unknown holder may cause the simulate to return a "not found" /
/// "HostStorageError" error; `classify_not_found` maps those to `Ok(0)`.
/// The caller should treat either as "no shares held".
///
/// # Simulate pattern provenance
///
/// Delegates to [`stellar_agent_defi::simulate::simulate_invoke_returning_scval`]
/// (dummy all-zeros G-strkey source, no auth, `build_for_simulation`) and
/// [`stellar_agent_defi::simulate::decode_i128_scval`] for i128 reconstruction.
///
/// # Arguments
///
/// - `vault_address` — C-strkey of the DeFindex vault / dfToken contract.
/// - `holder_address` — C-strkey (contract) or G-strkey (account) whose
///   share balance is queried.
/// - `rpc_url` — Soroban RPC URL.
/// - `network_passphrase` — Stellar network passphrase.
///
/// # Errors
///
/// Returns [`VaultShareBalanceFetchError`] on address-parse, simulate, or
/// decode failure.  A simulate error that looks like "not found" is silently
/// mapped to `Ok(0)` (the balance for an unknown holder is zero).
pub async fn read_vault_share_balance(
    vault_address: &str,
    holder_address: &str,
    rpc_url: &str,
    network_passphrase: &str,
) -> Result<i128, VaultShareBalanceFetchError> {
    // Parse holder address: try C-strkey first, then G-strkey.
    // The DeFindex vault token contract accepts both contract and account addresses.
    let holder_scval = parse_holder_address_to_scval(holder_address)?;

    // Delegate the simulate scaffold to the shared primitive.
    // Returns `Ok(None)` for an unknown holder (balance = 0); `Ok(Some(scval))`
    // for a successful result; `Err` for genuine failures.
    let maybe_scval =
        simulate_balance_returning_option(vault_address, holder_scval, rpc_url, network_passphrase)
            .await?;

    let result_scval = match maybe_scval {
        // Unknown holder → zero shares.
        None => return Ok(0),
        Some(v) => v,
    };

    stellar_agent_defi::simulate::decode_i128_scval(&result_scval).map_err(|e| {
        VaultShareBalanceFetchError::DecodeFailed {
            reason: format!("balance decode: {e}"),
        }
    })
}

/// Calls `simulate_invoke_returning_scval` for the vault `balance` entry point
/// and maps the result to `Ok(None)` for an unknown holder (zero shares) or
/// `Ok(Some(ScVal))` for a successful result.
///
/// Returns `Ok(None)` for an unknown-holder simulate error (balance = 0) or
/// `Ok(Some(ScVal))` for a successful result.  Uses a clean `Option`-based
/// return; the caller maps `None` to `Ok(0)` without any string comparison.
async fn simulate_balance_returning_option(
    vault_address: &str,
    holder_scval: stellar_xdr::ScVal,
    rpc_url: &str,
    network_passphrase: &str,
) -> Result<Option<stellar_xdr::ScVal>, VaultShareBalanceFetchError> {
    use stellar_agent_defi::simulate::SimulateError;

    stellar_agent_defi::simulate::simulate_invoke_returning_scval(
        vault_address,
        "balance",
        vec![holder_scval],
        rpc_url,
        network_passphrase,
    )
    .await
    .map(Some)
    .or_else(|e| match e {
        SimulateError::InvalidAddress { reason } => {
            Err(VaultShareBalanceFetchError::InvalidAddress { reason })
        }
        SimulateError::SimulateError { reason } => {
            // A "not found" / "HostStorageError" simulate error indicates the
            // holder has no balance entry → zero shares.
            if classify_not_found(&reason) {
                Ok(None)
            } else {
                Err(VaultShareBalanceFetchError::SimulateError { reason })
            }
        }
        SimulateError::SimulateFailed { reason } | SimulateError::DecodeFailed { reason } => {
            Err(VaultShareBalanceFetchError::SimulateFailed { reason })
        }
        SimulateError::NoResult => Err(VaultShareBalanceFetchError::SimulateFailed {
            reason: "simulate returned no result".to_owned(),
        }),
        // Forward-compat: future SimulateError variants are simulate failures.
        _ => Err(VaultShareBalanceFetchError::SimulateFailed {
            reason: e.to_string(),
        }),
    })
}

/// Returns `true` when a simulate error string indicates an unknown holder
/// (balance = 0) rather than a genuine contract error.
///
/// Only the two confirmed patterns ("not found" and "hoststorageerror") are
/// mapped to the zero-balance case.  Generic strings like "missing value" are
/// intentionally excluded — they may indicate a value-bearing call that
/// returned an unexpected error, which should surface as
/// [`VaultShareBalanceFetchError::SimulateError`] rather than `Ok(0)`.
fn classify_not_found(err: &str) -> bool {
    let lower = err.to_lowercase();
    lower.contains("not found") || lower.contains("hoststorageerror")
}

/// Parses a Stellar address string to a `stellar_xdr::ScVal::Address`.
///
/// Tries C-strkey (contract) first, then G-strkey (account).
///
/// # Errors
///
/// Returns `VaultShareBalanceFetchError::InvalidAddress` when neither parse
/// succeeds.
fn parse_holder_address_to_scval(
    address: &str,
) -> Result<stellar_xdr::ScVal, VaultShareBalanceFetchError> {
    use stellar_xdr::{AccountId, ContractId, PublicKey, ScAddress, Uint256};

    // Try C-strkey (contract address).
    if let Ok(c) = stellar_strkey::Contract::from_string(address) {
        let sc_addr = ScAddress::Contract(ContractId(Hash(c.0)));
        return Ok(stellar_xdr::ScVal::Address(sc_addr));
    }

    // Try G-strkey (ed25519 public key / account address).
    if let Ok(g) = stellar_strkey::ed25519::PublicKey::from_string(address) {
        let sc_addr = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(g.0))));
        return Ok(stellar_xdr::ScVal::Address(sc_addr));
    }

    Err(VaultShareBalanceFetchError::InvalidAddress {
        reason: format!(
            "address is neither a C-strkey (contract) nor a G-strkey (account): starts with '{}'",
            address.chars().next().unwrap_or('?')
        ),
    })
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
        reason = "test-only fixture construction"
    )]

    use super::*;

    // ── check_asset_count DoS bound ──────────────────────────────────────────

    #[test]
    fn check_asset_count_passes_at_max() {
        assert!(
            check_asset_count(MAX_VAULT_ASSETS).is_ok(),
            "count == MAX_VAULT_ASSETS must pass"
        );
    }

    #[test]
    fn check_asset_count_refuses_at_max_plus_one() {
        let result = check_asset_count(MAX_VAULT_ASSETS + 1);
        assert!(
            matches!(
                result,
                Err(VaultStorageFetchError::TooManyAssets {
                    count,
                    max
                }) if count == MAX_VAULT_ASSETS + 1 && max == MAX_VAULT_ASSETS
            ),
            "count == MAX_VAULT_ASSETS + 1 must return TooManyAssets; got {result:?}"
        );
    }

    #[test]
    fn check_asset_count_refuses_at_u32_max() {
        let result = check_asset_count(u32::MAX);
        assert!(
            matches!(result, Err(VaultStorageFetchError::TooManyAssets { .. })),
            "u32::MAX must return TooManyAssets; got {result:?}"
        );
    }

    #[test]
    fn too_many_assets_display_is_informative() {
        let err = VaultStorageFetchError::TooManyAssets {
            count: 17,
            max: MAX_VAULT_ASSETS,
        };
        let display = err.to_string();
        assert!(
            display.contains("17"),
            "display must mention the count: {display}"
        );
        assert!(
            display.contains(&MAX_VAULT_ASSETS.to_string()),
            "display must mention the max: {display}"
        );
    }

    // ── Upgradable ScVal key encoding ────────────────────────────────────────

    #[test]
    fn upgradable_scval_key_is_vec_with_symbol() {
        let key = build_upgradable_scval_key().unwrap();
        match &key {
            ScVal::Vec(Some(vec)) => {
                assert_eq!(vec.0.len(), 1, "Vec must have exactly one element");
                match &vec.0[0] {
                    ScVal::Symbol(sym) => {
                        assert_eq!(
                            sym.0.as_slice(),
                            b"Upgradable",
                            "symbol must be 'Upgradable'"
                        );
                    }
                    other => panic!("expected Symbol; got {other:?}"),
                }
            }
            other => panic!("expected Vec; got {other:?}"),
        }
    }

    #[test]
    fn unit_variant_key_for_manager_has_correct_symbol() {
        let key = build_unit_variant_scval_key("Manager").unwrap();
        match &key {
            ScVal::Vec(Some(vec)) => {
                assert_eq!(vec.0.len(), 1);
                match &vec.0[0] {
                    ScVal::Symbol(sym) => {
                        assert_eq!(sym.0.as_slice(), b"Manager");
                    }
                    other => panic!("expected Symbol; got {other:?}"),
                }
            }
            other => panic!("expected Vec; got {other:?}"),
        }
    }

    // ── classify_not_found ───────────────────────────────────────────────────

    #[test]
    fn classify_not_found_matches_known_patterns() {
        // "not found" in ledger (unknown holder path)
        assert!(
            classify_not_found("Error invoking contract function: not found in ledger"),
            "should match 'not found'"
        );
        // "hoststorageerror" (contract storage key missing)
        assert!(
            classify_not_found("HostStorageError: contract storage key not initialised"),
            "should match 'hoststorageerror'"
        );
        // case-insensitive
        assert!(
            classify_not_found("NOT FOUND"),
            "should match upper-case 'NOT FOUND'"
        );
    }

    #[test]
    fn classify_not_found_rejects_missing_value() {
        // "missing value" is too broad — must NOT route to Ok(0)
        assert!(
            !classify_not_found("missing value in map"),
            "'missing value' must not be classified as not-found"
        );
        assert!(
            !classify_not_found("unexpected error"),
            "generic errors must not be classified as not-found"
        );
        assert!(
            !classify_not_found(""),
            "empty string must not be classified as not-found"
        );
    }

    // ── build_instance_ledger_key rejects invalid strkeys ────────────────────

    #[test]
    fn invalid_vault_address_returns_error() {
        let result = build_instance_ledger_key("not-a-strkey");
        assert!(matches!(
            result,
            Err(VaultStorageFetchError::InvalidAddress { .. })
        ));
    }

    #[test]
    fn valid_vault_address_succeeds() {
        let result =
            build_instance_ledger_key("CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN");
        assert!(result.is_ok(), "valid C-strkey must parse: {result:?}");
    }

    // ── decode_asset_strategy_set_scval ─────────────────────────────────────

    /// Builds a minimal valid `AssetStrategySet` ScMap fixture for a contract address.
    ///
    /// Layout (alphabetically sorted, per soroban-sdk-macros 22.0.3):
    /// ScMap([{ key: Symbol("address"), val: Address }, { key: Symbol("strategies"), val: Vec([...]) }])
    fn make_asset_strategy_set_scval(
        asset_addr_bytes: [u8; 32],
        strategy_entries: Vec<ScVal>,
    ) -> ScVal {
        use stellar_xdr::{ContractId, ScAddress, ScMapEntry, ScVec, VecM};

        let addr_key = ScVal::Symbol(ScSymbol("address".try_into().unwrap()));
        let strat_key = ScVal::Symbol(ScSymbol("strategies".try_into().unwrap()));

        let asset_sc_addr = ScVal::Address(ScAddress::Contract(ContractId(Hash(asset_addr_bytes))));

        let strat_vec: VecM<ScVal> = strategy_entries.try_into().unwrap();
        let strat_sc_val = ScVal::Vec(Some(ScVec(strat_vec)));

        let map_entries: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: addr_key,
                val: asset_sc_addr,
            },
            ScMapEntry {
                key: strat_key,
                val: strat_sc_val,
            },
        ]
        .try_into()
        .unwrap();

        ScVal::Map(Some(stellar_xdr::ScMap(map_entries)))
    }

    /// Builds a `Strategy` ScMap fixture.
    fn make_strategy_scval(strategy_addr_bytes: [u8; 32], name: &str, paused: bool) -> ScVal {
        use stellar_xdr::{ContractId, ScAddress, ScMapEntry, ScString, StringM, VecM};

        let addr_key = ScVal::Symbol(ScSymbol("address".try_into().unwrap()));
        let name_key = ScVal::Symbol(ScSymbol("name".try_into().unwrap()));
        let paused_key = ScVal::Symbol(ScSymbol("paused".try_into().unwrap()));

        let sc_addr = ScVal::Address(ScAddress::Contract(ContractId(Hash(strategy_addr_bytes))));
        let name_str: StringM = name.as_bytes().to_vec().try_into().unwrap();
        let sc_name = ScVal::String(ScString(name_str));
        let sc_paused = ScVal::Bool(paused);

        let map_entries: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: addr_key,
                val: sc_addr,
            },
            ScMapEntry {
                key: name_key,
                val: sc_name,
            },
            ScMapEntry {
                key: paused_key,
                val: sc_paused,
            },
        ]
        .try_into()
        .unwrap();

        ScVal::Map(Some(stellar_xdr::ScMap(map_entries)))
    }

    #[test]
    fn decode_asset_strategy_set_well_formed_fixture() {
        use stellar_xdr::{ContractId, ScAddress};

        let asset_bytes = [0x11u8; 32];
        let strat_bytes = [0x22u8; 32];

        let strategy_scval = make_strategy_scval(strat_bytes, "blend_xlm_usdc", false);
        let asset_scval = make_asset_strategy_set_scval(asset_bytes, vec![strategy_scval]);

        let result = decode_asset_strategy_set_scval(&asset_scval)
            .expect("well-formed fixture must decode without error");

        // Address must round-trip to a C-strkey.
        let expected_addr = {
            let c = stellar_strkey::Contract(asset_bytes);
            format!("{}", stellar_strkey::Strkey::Contract(c))
        };
        assert_eq!(
            result.address, expected_addr,
            "asset address must match fixture"
        );

        assert_eq!(result.strategies.len(), 1, "must have exactly one strategy");
        let strat = &result.strategies[0];

        let expected_strat_addr = {
            let c = stellar_strkey::Contract(strat_bytes);
            format!("{}", stellar_strkey::Strkey::Contract(c))
        };
        assert_eq!(
            strat.address, expected_strat_addr,
            "strategy address must match fixture"
        );
        assert_eq!(
            strat.name, "blend_xlm_usdc",
            "strategy name must match fixture"
        );
        assert!(!strat.paused, "paused must be false");
        // Blend flag is always false at this layer; set by caller after WASM-hash lookup.
        assert!(
            !strat.is_blend_strategy,
            "is_blend_strategy must be false from decoder"
        );

        // Verify the decoded type exists and needed import is used.
        let _contract = stellar_strkey::Contract(asset_bytes);
        let _ = ScAddress::Contract(ContractId(Hash(asset_bytes)));
    }

    #[test]
    fn decode_asset_strategy_set_wrong_scval_type_returns_error() {
        // Passing a ScVal::Bool instead of a ScMap must return XdrError.
        let bad = ScVal::Bool(true);
        let result = decode_asset_strategy_set_scval(&bad);
        assert!(
            matches!(result, Err(VaultStorageFetchError::XdrError { .. })),
            "wrong ScVal type must return XdrError; got {result:?}"
        );
    }

    #[test]
    fn decode_asset_strategy_set_missing_strategies_key_returns_error() {
        use stellar_xdr::{ContractId, ScAddress, ScMapEntry, VecM};

        // Build a ScMap with only 'address', missing 'strategies'.
        let addr_key = ScVal::Symbol(ScSymbol("address".try_into().unwrap()));
        let asset_bytes = [0xAAu8; 32];
        let sc_addr = ScVal::Address(ScAddress::Contract(ContractId(Hash(asset_bytes))));

        let map_entries: VecM<ScMapEntry> = vec![ScMapEntry {
            key: addr_key,
            val: sc_addr,
        }]
        .try_into()
        .unwrap();
        let val = ScVal::Map(Some(stellar_xdr::ScMap(map_entries)));

        let result = decode_asset_strategy_set_scval(&val);
        assert!(
            matches!(result, Err(VaultStorageFetchError::XdrError { .. })),
            "missing 'strategies' key must return XdrError; got {result:?}"
        );
    }

    #[test]
    fn decode_strategy_absent_name_returns_empty_string() {
        use stellar_xdr::{ContractId, ScAddress, ScMapEntry, VecM};

        // Build a Strategy ScMap with only 'address' and 'paused' — 'name' absent.
        // The decoder must return name="" (the real behavior per the source comment).
        let addr_key = ScVal::Symbol(ScSymbol("address".try_into().unwrap()));
        let paused_key = ScVal::Symbol(ScSymbol("paused".try_into().unwrap()));

        let strat_bytes = [0x33u8; 32];
        let sc_addr = ScVal::Address(ScAddress::Contract(ContractId(Hash(strat_bytes))));

        let map_entries: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: addr_key,
                val: sc_addr,
            },
            ScMapEntry {
                key: paused_key,
                val: ScVal::Bool(true),
            },
        ]
        .try_into()
        .unwrap();
        let val = ScVal::Map(Some(stellar_xdr::ScMap(map_entries)));

        let result = decode_strategy_scval(&val)
            .expect("absent 'name' must decode to empty string, not error");

        assert_eq!(result.name, "", "absent 'name' must yield empty string");
        assert!(result.paused, "paused=true must be decoded correctly");
    }

    #[test]
    fn decode_strategy_wrong_address_type_returns_error() {
        use stellar_xdr::{ScMapEntry, VecM};

        // 'address' key present but value is Bool — must be XdrError.
        let addr_key = ScVal::Symbol(ScSymbol("address".try_into().unwrap()));
        let map_entries: VecM<ScMapEntry> = vec![ScMapEntry {
            key: addr_key,
            val: ScVal::Bool(false),
        }]
        .try_into()
        .unwrap();
        let val = ScVal::Map(Some(stellar_xdr::ScMap(map_entries)));

        let result = decode_strategy_scval(&val);
        assert!(
            matches!(result, Err(VaultStorageFetchError::XdrError { .. })),
            "wrong 'address' type must return XdrError; got {result:?}"
        );
    }

    #[test]
    fn find_address_in_scmap_absent_key_returns_error() {
        use stellar_xdr::{ScMapEntry, VecM};

        // Empty ScMap — 'address' key is absent.
        let map_entries: VecM<ScMapEntry> = vec![].try_into().unwrap();
        let map = stellar_xdr::ScMap(map_entries);

        let result = find_address_in_scmap(&map, "address");
        assert!(
            matches!(result, Err(VaultStorageFetchError::XdrError { .. })),
            "absent key must return XdrError; got {result:?}"
        );
    }

    #[test]
    fn decode_asset_strategy_set_empty_strategies_vec() {
        // ScVal::Vec(None) for the strategies field must return an empty strategies list.
        use stellar_xdr::{ContractId, ScAddress, ScMap, ScMapEntry, VecM};

        let addr_key = ScVal::Symbol(ScSymbol("address".try_into().unwrap()));
        let strat_key = ScVal::Symbol(ScSymbol("strategies".try_into().unwrap()));
        let asset_bytes = [0xBBu8; 32];
        let sc_addr = ScVal::Address(ScAddress::Contract(ContractId(Hash(asset_bytes))));

        let map_entries: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: addr_key,
                val: sc_addr,
            },
            ScMapEntry {
                key: strat_key,
                val: ScVal::Vec(None),
            },
        ]
        .try_into()
        .unwrap();
        let val = ScVal::Map(Some(ScMap(map_entries)));

        let result = decode_asset_strategy_set_scval(&val)
            .expect("ScVal::Vec(None) strategies must decode to empty list");
        assert!(result.strategies.is_empty(), "strategies must be empty");
    }

    // ── DoS: depth-bomb is rejected by untrusted_decode_limits ──────────────

    #[test]
    fn ledger_entry_data_decode_rejects_depth_bomb() {
        use stellar_xdr::{
            ContractDataDurability, ContractDataEntry, ContractId, ExtensionPoint, Hash,
            LedgerEntryData, ScAddress, ScVal, ScVec, WriteXdr,
        };

        // Build a 501-level nested ScVal::Vec iteratively (no recursion in the
        // builder), wrapped in a LedgerEntryData::ContractData. The structure is
        // valid XDR but its decode depth exceeds the 500-level bound enforced by
        // `untrusted_decode_limits` at both decode sites in this module.
        let mut val = ScVal::Void;
        for _ in 0..501 {
            let inner: stellar_xdr::VecM<ScVal> =
                vec![val].try_into().expect("single-element VecM");
            val = ScVal::Vec(Some(ScVec(inner)));
        }
        let entry = LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val,
        });
        // Encode with Limits::none() on the write side — the value is valid XDR,
        // just nested past the read-side depth bound.
        let bomb_b64 = entry
            .to_xdr_base64(stellar_xdr::Limits::none())
            .expect("write side with no limits must succeed");

        // The bounded decode must reject the depth-bomb.
        let decode_result = LedgerEntryData::from_xdr_base64(
            &bomb_b64,
            stellar_agent_xdr_limits::untrusted_decode_limits(bomb_b64.len()),
        );
        assert!(
            decode_result.is_err(),
            "a depth-bomb LedgerEntryData must be rejected by untrusted_decode_limits; \
             a reversion to Limits::none() would let this succeed"
        );
    }
}
