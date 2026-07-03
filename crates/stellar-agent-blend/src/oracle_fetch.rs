//! Oracle and pool-config fetch helpers for the ordered trust gate.
//!
//! # What this module does
//!
//! Provides three asynchronous read operations used in the ordered trust gate:
//!
//! - [`read_pool_reserve_list`] — reads the pool's reserve asset list from
//!   persistent contract storage via `getLedgerEntries`.
//!
//! - [`read_pool_oracle_address`] — reads the pool's `PoolConfig.oracle` address
//!   from the contract instance storage via `getLedgerEntries` (step 2 input).
//!
//! - [`query_oracle_lastprice_timestamps`] — calls the oracle's `lastprice`
//!   function for each touched reserve asset via a read-only simulate
//!   (step 3 input for [`crate::oracle::OracleStalenessSnapshot`] construction).
//!
//! None of these modify chain state.  All are fail-closed: on any error they
//! return `Err`, which causes the ordered gate to refuse.
//!
//! # Ordered trust invariant
//!
//! These functions MUST be called AFTER `verify_blend_pool_wasm` (step 1).
//! The dispatch site enforces this with `?`-early-return sequencing.
//!
//! # ABI provenance
//!
//! - `PoolConfig.oracle` field: `blend-contracts-v2 pool/src/storage.rs`.
//! - Pool instance storage key: `Symbol("Config")` at `storage.rs`.
//! - Reflector `lastprice(Asset)` function: SEP-40 oracle interface; verified
//!   on-chain.

use stellar_agent_network::StellarRpcClient;
use stellar_agent_xdr_limits::untrusted_decode_limits;
use stellar_xdr::{
    ContractDataDurability, ContractId, Hash, LedgerEntryData, LedgerKey, LedgerKeyContractData,
    ReadXdr, ScAddress, ScSymbol, ScVal,
};

// ─────────────────────────────────────────────────────────────────────────────
// PoolOracleFetchError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned by pool-config and oracle fetch operations.
///
/// All variants carry non-sensitive diagnostic information; the `Display` impl
/// NEVER leaks pool addresses, oracle addresses, or full hashes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PoolOracleFetchError {
    /// The pool or asset contract address could not be parsed.
    #[error("invalid contract address: {reason}")]
    InvalidAddress {
        /// Non-sensitive reason.
        reason: String,
    },
    /// The `getLedgerEntries` call failed.
    #[error("RPC getLedgerEntries failed: {reason}")]
    LedgerFetchFailed {
        /// Non-sensitive reason (URL redacted by the network layer).
        reason: String,
    },
    /// The pool contract instance entry was not found.
    #[error("pool contract instance not found on ledger")]
    InstanceNotFound,
    /// The contract instance storage did not contain `PoolConfig`.
    #[error("PoolConfig not found in pool instance storage (key 'Config' absent)")]
    PoolConfigNotFound,
    /// The `oracle` field inside `PoolConfig` could not be decoded.
    #[error("PoolConfig.oracle decode failed: {reason}")]
    OracleAddressDecode {
        /// Non-sensitive reason.
        reason: String,
    },
    /// The oracle `lastprice` simulate call failed.
    #[error("oracle lastprice simulate failed: {reason}")]
    OraclePriceSimulateFailed {
        /// Non-sensitive reason.
        reason: String,
    },
    /// The oracle `lastprice` returned no result (asset not tracked).
    #[error("oracle lastprice returned no price data for asset")]
    OraclePriceAbsent,
    /// Oracle price data could not be decoded.
    #[error("oracle lastprice result decode failed: {reason}")]
    OraclePriceDecodeFailed {
        /// Non-sensitive reason.
        reason: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// read_pool_reserve_list
// ─────────────────────────────────────────────────────────────────────────────

/// Reads the pool's reserve asset list (`Vec<Address>`) from on-chain persistent
/// storage.
///
/// The reserve list is stored as a persistent `ContractData` entry with key
/// `ScVal::Symbol("ResList")`.
///
/// # ABI provenance
///
/// - Storage key constant: `blend-contracts-v2 pool/src/storage.rs`
///   — `const RES_LIST_KEY: &str = "ResList"`.
/// - Storage durability: `persistent`, `get_persistent_default` at
///   `storage.rs`.
/// - On-chain layout: `Vec<Address>`, each element is `ScVal::Address`.
///
/// # Returns
///
/// Returns a `Vec<String>` of C-strkeys for the reserve asset addresses.
/// Returns an empty `Vec` when the pool has no reserves configured yet.
///
/// # Errors
///
/// Returns [`PoolOracleFetchError`] on any failure. Fail-closed.
pub async fn read_pool_reserve_list(
    pool_address: &str,
    rpc: &StellarRpcClient,
) -> Result<Vec<String>, PoolOracleFetchError> {
    // Build the LedgerKey for `ContractData { contract, key: Symbol("ResList"),
    // durability: Persistent }`.
    // Cited: blend-contracts-v2 pool/src/storage.rs.
    let contract = stellar_strkey::Contract::from_string(pool_address).map_err(|e| {
        PoolOracleFetchError::InvalidAddress {
            reason: format!("pool address invalid: {e}"),
        }
    })?;
    let hash = Hash(contract.0);
    let sc_addr = ScAddress::Contract(ContractId(hash));

    // Blend stores the reserve list under a BARE Symbol persistent key
    // (`Symbol::new(e, "ResList")` — blend-contracts-v2 pool/src/storage.rs at
    // the pinned clone), NOT a #[contracttype] enum variant; the bare
    // ScVal::Symbol form below is the correct on-chain encoding for this key.
    let res_list_sym = ScSymbol(b"ResList".as_slice().try_into().map_err(|_| {
        PoolOracleFetchError::OracleAddressDecode {
            reason: "ResList symbol too long (should never happen)".to_owned(),
        }
    })?);
    let ledger_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: sc_addr,
        key: ScVal::Symbol(res_list_sym),
        durability: ContractDataDurability::Persistent,
    });

    let response = rpc.get_ledger_entries(&[ledger_key]).await.map_err(|e| {
        PoolOracleFetchError::LedgerFetchFailed {
            reason: e.to_string(),
        }
    })?;

    let entries = response.entries.unwrap_or_default();
    if entries.is_empty() {
        // No reserves configured yet — empty list is valid.
        return Ok(vec![]);
    }

    for entry_result in &entries {
        let entry_data = decode_ledger_entry_data(&entry_result.xdr)?;

        if let LedgerEntryData::ContractData(cd) = &entry_data {
            return extract_address_vec_from_scval(&cd.val);
        }
    }

    Ok(vec![])
}

/// Extracts a `Vec<String>` of C-strkeys from a `ScVal::Vec(Some([Address, ...]))`.
///
/// The Blend pool stores `Vec<Address>` as a soroban contracttype Vec.
fn extract_address_vec_from_scval(val: &ScVal) -> Result<Vec<String>, PoolOracleFetchError> {
    match val {
        ScVal::Vec(Some(vec)) => {
            let mut addrs = Vec::with_capacity(vec.len());
            for item in vec.iter() {
                let addr = sc_address_to_strkey(item)?;
                addrs.push(addr);
            }
            Ok(addrs)
        }
        ScVal::Vec(None) | ScVal::Void => Ok(vec![]),
        _ => Err(PoolOracleFetchError::OracleAddressDecode {
            reason: "reserve list is not ScVal::Vec; got a different variant".to_string(),
        }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// read_pool_oracle_address
// ─────────────────────────────────────────────────────────────────────────────

/// Reads the `PoolConfig.oracle` address from a Blend pool's contract instance.
///
/// Uses `getLedgerEntries` to fetch the pool's contract instance entry, then
/// extracts the `"Config"` symbol entry from the instance storage map and
/// decodes the `oracle` field.
///
/// # Step in the ordered gate
///
/// This is the input to **step 2** (oracle-allowlist check). Call AFTER
/// `verify_blend_pool_wasm` (step 1) passes.
///
/// # ABI provenance
///
/// `PoolConfig.oracle: Address` at `blend-contracts-v2 pool/src/storage.rs`
/// (v2).  Instance storage key: `Symbol("Config")` at
/// `storage.rs` (v2).  `PoolConfig` is a `#[contracttype]`
/// struct; fields are sorted alphabetically by soroban-sdk
/// `derive_struct.rs`.
///
/// # Errors
///
/// Returns [`PoolOracleFetchError`] on any failure. All errors are fail-closed.
pub async fn read_pool_oracle_address(
    pool_address: &str,
    rpc: &StellarRpcClient,
) -> Result<String, PoolOracleFetchError> {
    let key = contract_instance_ledger_key(pool_address)?;

    let response = rpc.get_ledger_entries(&[key]).await.map_err(|e| {
        PoolOracleFetchError::LedgerFetchFailed {
            reason: e.to_string(),
        }
    })?;

    let entries = response.entries.unwrap_or_default();
    if entries.is_empty() {
        return Err(PoolOracleFetchError::InstanceNotFound);
    }

    for entry_result in &entries {
        let entry_data = decode_ledger_entry_data(&entry_result.xdr)?;

        if let LedgerEntryData::ContractData(cd) = &entry_data
            && let ScVal::ContractInstance(instance) = &cd.val
        {
            let storage = instance
                .storage
                .as_ref()
                .ok_or(PoolOracleFetchError::PoolConfigNotFound)?;
            for map_entry in storage.iter() {
                if let ScVal::Symbol(sym) = &map_entry.key
                    && sym.0.as_slice() == b"Config"
                {
                    return extract_oracle_from_pool_config_scval(&map_entry.val);
                }
            }
            return Err(PoolOracleFetchError::PoolConfigNotFound);
        }
    }

    Err(PoolOracleFetchError::InstanceNotFound)
}

/// Extracts the `oracle` address from a `PoolConfig` `ScVal::Map`.
///
/// Searches by key symbol name `"oracle"` rather than by index, to be robust
/// against future `PoolConfig` field additions.
///
/// # ABI provenance
///
/// `PoolConfig` at `blend-contracts-v2 pool/src/storage.rs`.
/// Field names: `bstop_rate`, `max_positions`, `min_collateral`, `oracle`, `status`.
/// Sorted alphabetically per soroban-sdk `derive_struct.rs`.
fn extract_oracle_from_pool_config_scval(val: &ScVal) -> Result<String, PoolOracleFetchError> {
    let entries = match val {
        ScVal::Map(Some(m)) => m,
        _ => {
            return Err(PoolOracleFetchError::OracleAddressDecode {
                reason: "PoolConfig value is not ScVal::Map".to_owned(),
            });
        }
    };

    for entry in entries.iter() {
        if let ScVal::Symbol(key_sym) = &entry.key
            && key_sym.0.as_slice() == b"oracle"
        {
            return sc_address_to_strkey(&entry.val);
        }
    }

    Err(PoolOracleFetchError::OracleAddressDecode {
        reason: "oracle field not found in PoolConfig map".to_owned(),
    })
}

/// Converts a `ScVal::Address(ScAddress::Contract(...))` to a C-strkey.
fn sc_address_to_strkey(val: &ScVal) -> Result<String, PoolOracleFetchError> {
    match val {
        ScVal::Address(ScAddress::Contract(ContractId(Hash(bytes)))) => {
            let contract = stellar_strkey::Contract(*bytes);
            // stellar_strkey::Strkey::to_string() returns a heapless::String;
            // convert to std::String via Display formatting.
            Ok(format!("{}", stellar_strkey::Strkey::Contract(contract)))
        }
        _ => Err(PoolOracleFetchError::OracleAddressDecode {
            reason: "oracle field is not ScVal::Address(Contract)".to_owned(),
        }),
    }
}

/// Constructs the `LedgerKey::ContractData` for a contract's instance entry.
fn contract_instance_ledger_key(address: &str) -> Result<LedgerKey, PoolOracleFetchError> {
    let contract = stellar_strkey::Contract::from_string(address).map_err(|e| {
        PoolOracleFetchError::InvalidAddress {
            reason: e.to_string(),
        }
    })?;
    let hash = Hash(contract.0);
    let sc_addr = ScAddress::Contract(ContractId(hash));
    Ok(LedgerKey::ContractData(LedgerKeyContractData {
        contract: sc_addr,
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    }))
}

/// Decodes an untrusted base64 `LedgerEntryData` from an RPC `getLedgerEntries`
/// response under depth + length bounds, refusing a depth-bomb DoS.
///
/// The RPC server is untrusted (user-configured, possibly malicious or
/// MITM-tampered), so the entry XDR is bounded via
/// [`untrusted_decode_limits`] rather than `Limits::none()`.
fn decode_ledger_entry_data(xdr_b64: &str) -> Result<LedgerEntryData, PoolOracleFetchError> {
    LedgerEntryData::from_xdr_base64(xdr_b64, untrusted_decode_limits(xdr_b64.len())).map_err(|e| {
        PoolOracleFetchError::OracleAddressDecode {
            reason: format!("LedgerEntryData XDR decode failed: {e}"),
        }
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// query_oracle_lastprice_timestamps
// ─────────────────────────────────────────────────────────────────────────────

/// Queries the Reflector oracle for `lastprice` timestamps for the given asset
/// addresses.
///
/// For each asset address in `asset_addresses`, calls the oracle contract's
/// `lastprice(Asset::Stellar(asset))` via a read-only simulate and collects
/// the returned UNIX timestamps.
///
/// # SEP-40 oracle interface
///
/// Reflector oracle `lastprice` signature:
/// `lastprice(asset: Asset) -> Option<PriceData>`
/// where `Asset::Stellar(contract: Address)` selects a token by SAC/contract
/// address, and `PriceData { price: i128, timestamp: u64 }`.
///
/// Verified on-chain:
/// `lastprice --asset '{"Stellar": "CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75"}'`
/// → `{"price":"10008096","timestamp":1780572600}`.
///
/// # Step in the ordered gate
///
/// This is **step 3** of the ordered gate. Call AFTER step 2 (allowlist check)
/// passes.
///
/// # Errors
///
/// Returns [`PoolOracleFetchError`] on any failure. Fail-closed.
pub async fn query_oracle_lastprice_timestamps(
    oracle_address: &str,
    asset_addresses: &[String],
    rpc_url: &str,
    network_passphrase: &str,
) -> Result<Vec<u64>, PoolOracleFetchError> {
    if asset_addresses.is_empty() {
        return Ok(vec![]);
    }

    let mut timestamps = Vec::with_capacity(asset_addresses.len());

    for asset_addr in asset_addresses {
        let ts =
            query_single_lastprice(oracle_address, asset_addr, rpc_url, network_passphrase).await?;
        timestamps.push(ts);
    }

    Ok(timestamps)
}

/// Queries `lastprice(Asset::Stellar(asset))` on the oracle for a single asset.
///
/// Delegates to [`stellar_agent_defi::reflector::query_reflector_lastprice`].
/// The defi-layer function owns
/// the ABI encoding, price > 0 guard, and PriceData decode logic; this function
/// is the Blend-specific error-mapping shim that converts
/// [`stellar_agent_defi::reflector::ReflectorError`] to
/// [`PoolOracleFetchError`] and projects out the timestamp (`u64`).
///
/// # Security: price > 0
///
/// `query_reflector_lastprice` returns `Err(ReflectorError::PriceAbsent)` when
/// `price <= 0`.  This maps to
/// `Err(PoolOracleFetchError::OraclePriceAbsent)`.
async fn query_single_lastprice(
    oracle_address: &str,
    asset_address: &str,
    rpc_url: &str,
    network_passphrase: &str,
) -> Result<u64, PoolOracleFetchError> {
    use stellar_agent_defi::reflector::{ReflectorError, query_reflector_lastprice};

    let (_price, timestamp) =
        query_reflector_lastprice(oracle_address, asset_address, rpc_url, network_passphrase)
            .await
            .map_err(|e| match e {
                ReflectorError::InvalidAddress { reason } => {
                    PoolOracleFetchError::InvalidAddress { reason }
                }
                ReflectorError::SimulateFailed { reason } => {
                    PoolOracleFetchError::OraclePriceSimulateFailed { reason }
                }
                ReflectorError::PriceAbsent => PoolOracleFetchError::OraclePriceAbsent,
                ReflectorError::DecodeFailed { reason } => {
                    PoolOracleFetchError::OraclePriceDecodeFailed { reason }
                }
                // Non-exhaustive: map any future variants to simulate-failed.
                e => PoolOracleFetchError::OraclePriceSimulateFailed {
                    reason: format!("Reflector query failed: {e}"),
                },
            })?;

    Ok(timestamp)
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
    use stellar_xdr::{ScMap, ScMapEntry, ScSymbol, StringM};

    /// A known, structurally-valid C-strkey for contract addresses.
    const ORACLE_STRKEY: &str = "CCVTVW2CVA7JLH4ROQGP3CU4T3EXVCK66AZGSM4MUQPXAI4QHCZPOATS";
    /// A second distinct C-strkey for multi-element tests.
    const RESERVE_STRKEY: &str = "CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF";

    // ── Fixture helpers ────────────────────────────────────────────────────

    /// Builds a `ScVal::Address(ScAddress::Contract(..))` from a C-strkey.
    fn c_strkey_to_scval_address(strkey: &str) -> ScVal {
        let bytes = stellar_strkey::Contract::from_string(strkey)
            .expect("valid C-strkey")
            .0;
        ScVal::Address(ScAddress::Contract(ContractId(Hash(bytes))))
    }

    /// Builds a `ScMapEntry` with a `ScVal::Symbol` key.
    fn sym_entry(name: &str, val: ScVal) -> ScMapEntry {
        let key_str: StringM<32> = name.try_into().expect("symbol name fits in 32 bytes");
        ScMapEntry {
            key: ScVal::Symbol(ScSymbol(key_str)),
            val,
        }
    }

    // ── extract_address_vec_from_scval ─────────────────────────────────────

    #[test]
    fn extract_address_vec_two_contracts_round_trip() {
        // Build ScVal::Vec(Some([Address(Contract1), Address(Contract2)])).
        let addr1 = c_strkey_to_scval_address(ORACLE_STRKEY);
        let addr2 = c_strkey_to_scval_address(RESERVE_STRKEY);
        let vec_m: stellar_xdr::VecM<ScVal> =
            vec![addr1, addr2].try_into().expect("vec conversion");
        let val = ScVal::Vec(Some(stellar_xdr::ScVec(vec_m)));

        let result = extract_address_vec_from_scval(&val).expect("valid Vec of Addresses");

        assert_eq!(result.len(), 2, "must return exactly 2 strkeys");
        assert_eq!(
            result[0], ORACLE_STRKEY,
            "first strkey must round-trip to {ORACLE_STRKEY}"
        );
        assert_eq!(
            result[1], RESERVE_STRKEY,
            "second strkey must round-trip to {RESERVE_STRKEY}"
        );
    }

    #[test]
    fn extract_address_vec_none_returns_empty() {
        let val = ScVal::Vec(None);
        let result = extract_address_vec_from_scval(&val).expect("Vec(None) must return empty vec");
        assert!(
            result.is_empty(),
            "Vec(None) must return an empty vec, got {result:?}"
        );
    }

    #[test]
    fn extract_address_vec_void_returns_empty() {
        let result =
            extract_address_vec_from_scval(&ScVal::Void).expect("Void must return empty vec");
        assert!(
            result.is_empty(),
            "Void must return an empty vec, got {result:?}"
        );
    }

    #[test]
    fn extract_address_vec_wrong_variant_returns_err() {
        let err = extract_address_vec_from_scval(&ScVal::Bool(true))
            .expect_err("Bool must not parse as address vec");
        assert!(
            matches!(err, PoolOracleFetchError::OracleAddressDecode { .. }),
            "expected OracleAddressDecode, got {err:?}"
        );
    }

    // ── extract_oracle_from_pool_config_scval ──────────────────────────────

    #[test]
    fn extract_oracle_from_pool_config_finds_oracle_key() {
        // Build a PoolConfig-shaped ScVal::Map containing an "oracle" entry.
        let oracle_val = c_strkey_to_scval_address(ORACLE_STRKEY);
        let entries: Vec<ScMapEntry> = vec![
            sym_entry("bstop_rate", ScVal::U32(200)),
            sym_entry("max_positions", ScVal::U32(4)),
            sym_entry("oracle", oracle_val),
            sym_entry("status", ScVal::U32(0)),
        ];
        let sc_map = ScMap(entries.try_into().expect("map conversion"));
        let val = ScVal::Map(Some(sc_map));

        let result = extract_oracle_from_pool_config_scval(&val).expect("oracle key must be found");

        assert_eq!(
            result, ORACLE_STRKEY,
            "oracle strkey must round-trip to {ORACLE_STRKEY}"
        );
    }

    #[test]
    fn extract_oracle_from_pool_config_missing_oracle_key_returns_err() {
        // Map without an "oracle" key.
        let entries: Vec<ScMapEntry> = vec![
            sym_entry("bstop_rate", ScVal::U32(200)),
            sym_entry("status", ScVal::U32(0)),
        ];
        let sc_map = ScMap(entries.try_into().expect("map conversion"));
        let val = ScVal::Map(Some(sc_map));

        let err = extract_oracle_from_pool_config_scval(&val)
            .expect_err("missing oracle key must return Err");
        assert!(
            matches!(err, PoolOracleFetchError::OracleAddressDecode { .. }),
            "expected OracleAddressDecode for missing oracle key, got {err:?}"
        );
    }

    #[test]
    fn extract_oracle_from_pool_config_non_map_returns_err() {
        let err = extract_oracle_from_pool_config_scval(&ScVal::Bool(true))
            .expect_err("non-Map must return Err");
        assert!(
            matches!(err, PoolOracleFetchError::OracleAddressDecode { .. }),
            "expected OracleAddressDecode for non-Map, got {err:?}"
        );
    }

    #[test]
    fn extract_oracle_from_pool_config_u32_returns_err() {
        let err = extract_oracle_from_pool_config_scval(&ScVal::U32(42))
            .expect_err("U32 must return Err");
        assert!(
            matches!(err, PoolOracleFetchError::OracleAddressDecode { .. }),
            "expected OracleAddressDecode for U32 variant, got {err:?}"
        );
    }

    // ── sc_address_to_strkey ───────────────────────────────────────────────

    #[test]
    fn sc_address_to_strkey_contract_address_returns_correct_strkey() {
        let val = c_strkey_to_scval_address(ORACLE_STRKEY);
        let result = sc_address_to_strkey(&val).expect("valid Contract address must succeed");
        assert_eq!(
            result, ORACLE_STRKEY,
            "strkey must round-trip through ScAddress::Contract"
        );
    }

    #[test]
    fn sc_address_to_strkey_non_address_variant_returns_err() {
        let err =
            sc_address_to_strkey(&ScVal::Bool(true)).expect_err("Bool must not be an address");
        assert!(
            matches!(err, PoolOracleFetchError::OracleAddressDecode { .. }),
            "expected OracleAddressDecode for Bool variant, got {err:?}"
        );
    }

    #[test]
    fn sc_address_to_strkey_void_returns_err() {
        let err = sc_address_to_strkey(&ScVal::Void).expect_err("Void must not be an address");
        assert!(
            matches!(err, PoolOracleFetchError::OracleAddressDecode { .. }),
            "expected OracleAddressDecode for Void, got {err:?}"
        );
    }

    // ── contract_instance_ledger_key ───────────────────────────────────────

    #[test]
    fn contract_instance_ledger_key_valid_strkey_produces_persistent_key() {
        let key = contract_instance_ledger_key(ORACLE_STRKEY)
            .expect("valid C-strkey must produce a LedgerKey");

        match key {
            LedgerKey::ContractData(ref cd) => {
                // The contract field must encode the same bytes as the input strkey.
                let expected_bytes = stellar_strkey::Contract::from_string(ORACLE_STRKEY)
                    .expect("canonical parse")
                    .0;
                match &cd.contract {
                    ScAddress::Contract(ContractId(Hash(bytes))) => {
                        assert_eq!(
                            *bytes, expected_bytes,
                            "contract field bytes must match the input strkey"
                        );
                    }
                    other => panic!("expected ScAddress::Contract, got {other:?}"),
                }
                assert_eq!(
                    cd.durability,
                    ContractDataDurability::Persistent,
                    "durability must be Persistent"
                );
            }
            other => panic!("expected LedgerKey::ContractData, got {other:?}"),
        }
    }

    #[test]
    fn contract_instance_ledger_key_invalid_strkey_returns_err() {
        let err =
            contract_instance_ledger_key("GAHJJJKMOKYE4RVPZEWZTKH5FVI4PA3VL7GK2LFNUBSGBV3CK4KJDJ")
                .expect_err("G-strkey must return Err");
        assert!(
            matches!(err, PoolOracleFetchError::InvalidAddress { .. }),
            "expected InvalidAddress for G-strkey, got {err:?}"
        );
    }

    #[test]
    fn contract_instance_ledger_key_garbage_returns_err() {
        let err = contract_instance_ledger_key("garbage-input-not-a-strkey")
            .expect_err("garbage must return Err");
        assert!(
            matches!(err, PoolOracleFetchError::InvalidAddress { .. }),
            "expected InvalidAddress for garbage input, got {err:?}"
        );
    }

    // ── extract_oracle_from_pool_config_scval with wrong type ─────────────

    #[test]
    fn extract_oracle_wrong_type_returns_error() {
        let result = extract_oracle_from_pool_config_scval(&ScVal::Bool(true));
        assert!(
            matches!(
                result,
                Err(PoolOracleFetchError::OracleAddressDecode { .. })
            ),
            "wrong type must return OracleAddressDecode"
        );
    }

    #[test]
    fn decode_ledger_entry_data_rejects_depth_bomb() {
        use stellar_xdr::{ContractDataEntry, ExtensionPoint, ScVec, WriteXdr};

        // Build a 501-level nested ScVal::Vec iteratively (no recursion in the
        // builder), wrapped in a LedgerEntryData::ContractData. The structure is
        // valid XDR but its decode depth exceeds the 500-level bound applied to
        // untrusted RPC responses by `untrusted_decode_limits`.
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

        let err = decode_ledger_entry_data(&bomb_b64)
            .expect_err("a depth-bomb LedgerEntryData must be rejected by the decode bound");
        assert!(
            matches!(err, PoolOracleFetchError::OracleAddressDecode { .. }),
            "expected OracleAddressDecode for the depth-bomb; a reversion to \
             Limits::none() would let this decode succeed: {err:?}"
        );
    }
}
