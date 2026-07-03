//! Generic Reflector oracle `lastprice` query.
//!
//! # What this module does
//!
//! Provides [`query_reflector_lastprice`]: a generic SEP-40 Reflector oracle
//! `lastprice(Asset::Stellar(asset))` query via read-only simulate, returning
//! `(price: i128, timestamp: u64)`.
//!
//! This function is the protocol-agnostic Reflector oracle query.
//! `stellar-agent-blend::oracle_fetch::query_single_lastprice` is the
//! Blend-specific layer; it delegates to this function for the raw
//! price/timestamp query.
//!
//! No Blend-specific logic is present here.  The `Asset::Stellar(Address)`
//! encoding is the SEP-40 standard used by Reflector.
//!
//! # ABI provenance
//!
//! `Asset::Stellar(Address)` encodes as:
//! `ScVal::Map([{ key: Symbol("Stellar"), val: Address(...) }])`
//! per soroban-sdk contracttype enum-map derive
//! (`rs-soroban-sdk/soroban-sdk-macros/src/derive_enum_map.rs` @ `dcbea44`).
//!
//! `PriceData` fields, alphabetically: `price` < `timestamp`.
//! Return type `Option<PriceData>` per `soroban-env-common/src/option.rs:3-16`:
//! - `ScVal::Void` for `None`.
//! - Raw `PriceData` `ScVal::Map(...)` for `Some`.
//!
//! # Security: price > 0
//!
//! A rogue-but-allowlisted oracle returning `{price: 0, timestamp: fresh}`
//! MUST NOT pass. A zero or negative price means the oracle has no valid data.
//! This function returns `Err(ReflectorError::PriceAbsent)` for `price <= 0`.

// ─────────────────────────────────────────────────────────────────────────────
// ReflectorError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned by [`query_reflector_lastprice`].
///
/// All variants carry non-sensitive diagnostic information.  The `Display`
/// impl never leaks full `C…` addresses.
///
/// # Sibling-variant Display audit
///
/// Every variant is reviewed: none echoes a full address in its `Display`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReflectorError {
    /// An oracle or asset address is not a valid C-strkey.
    #[error("invalid oracle or asset address: {reason}")]
    InvalidAddress {
        /// Non-sensitive reason.
        reason: String,
    },

    /// The simulate call failed.
    #[error("Reflector lastprice simulate failed: {reason}")]
    SimulateFailed {
        /// Non-sensitive reason.
        reason: String,
    },

    /// The simulate returned no result value.
    #[error("Reflector lastprice returned no result (oracle has no price for this asset)")]
    PriceAbsent,

    /// The return value could not be decoded as `PriceData`.
    #[error("Reflector PriceData decode failed: {reason}")]
    DecodeFailed {
        /// Non-sensitive reason.
        reason: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// query_reflector_lastprice
// ─────────────────────────────────────────────────────────────────────────────

/// Queries `lastprice(Asset::Stellar(asset))` on a SEP-40 Reflector oracle.
///
/// Returns `(price, timestamp)` where:
/// - `price` is the oracle price (`i128`); always `> 0` (price-zero = absent).
/// - `timestamp` is the Unix ledger-close timestamp of the price entry (`u64`).
///
/// Performs a read-only simulate via the shared
/// [`crate::simulate::simulate_invoke_returning_scval`] primitive (backed by
/// `stellar_rpc_client::Client::simulate_transaction_envelope`).
/// No auth entries and no signing are required.
///
/// # Arguments
///
/// - `oracle_address` — Reflector oracle C-strkey.
/// - `asset_address` — Asset SAC C-strkey for `Asset::Stellar(address)` arg.
/// - `rpc_url` — Soroban RPC URL.
/// - `network_passphrase` — Stellar network passphrase.
///
/// # ABI provenance
///
/// `Asset::Stellar(Address)` encoding:
/// `ScVal::Map([{ key: Symbol("Stellar"), val: Address(...) }])`
/// per soroban-sdk contracttype enum-map derive at `dcbea44`.
///
/// `PriceData.price: i128`, `PriceData.timestamp: u64`, alphabetical order
/// per `derive_struct.rs:33` @ `dcbea44`.
///
/// # Security: price > 0
///
/// Returns `Err(ReflectorError::PriceAbsent)` when `price <= 0`, treating
/// zero/negative price as an absent/invalid oracle entry.
///
/// # Errors
///
/// Returns [`ReflectorError`] on any address-parse, simulate, or decode failure.
pub async fn query_reflector_lastprice(
    oracle_address: &str,
    asset_address: &str,
    rpc_url: &str,
    network_passphrase: &str,
) -> Result<(i128, u64), ReflectorError> {
    use stellar_xdr::{
        ContractId, Hash, ScAddress, ScMap, ScMapEntry, ScSymbol, ScVal, StringM, VecM,
    };

    // Parse oracle address (only needed for error message; the shared
    // simulate_invoke_returning_scval re-parses it internally).
    stellar_strkey::Contract::from_string(oracle_address).map_err(|e| {
        ReflectorError::InvalidAddress {
            reason: format!("oracle address parse failed: {e}"),
        }
    })?;

    // Parse asset address.
    let asset_bytes = stellar_strkey::Contract::from_string(asset_address)
        .map_err(|e| ReflectorError::InvalidAddress {
            reason: format!("asset address parse failed: {e}"),
        })?
        .0;
    let asset_sc_addr = ScAddress::Contract(ContractId(Hash(asset_bytes)));

    // Asset::Stellar(Address) encodes as ScVal::Map([{Symbol("Stellar"), Address}]).
    // Per soroban-sdk contracttype enum-map derive at dcbea44.
    let stellar_sym: StringM<32> =
        "Stellar"
            .try_into()
            .map_err(|_| ReflectorError::SimulateFailed {
                reason: "Symbol 'Stellar' exceeds 32 bytes (unexpected)".to_owned(),
            })?;
    let asset_map_entry = ScMapEntry {
        key: ScVal::Symbol(ScSymbol(stellar_sym)),
        val: ScVal::Address(asset_sc_addr),
    };
    let asset_map_vec: VecM<ScMapEntry> =
        vec![asset_map_entry]
            .try_into()
            .map_err(|_| ReflectorError::SimulateFailed {
                reason: "ScMap vec conversion failed (unexpected)".to_owned(),
            })?;
    let asset_scval = ScVal::Map(Some(ScMap(asset_map_vec)));

    // Delegate the simulate scaffold to the shared primitive.
    let result_scval = crate::simulate::simulate_invoke_returning_scval(
        oracle_address,
        "lastprice",
        vec![asset_scval],
        rpc_url,
        network_passphrase,
    )
    .await
    .map_err(|e| match e {
        crate::simulate::SimulateError::InvalidAddress { reason } => {
            ReflectorError::InvalidAddress { reason }
        }
        crate::simulate::SimulateError::NoResult => ReflectorError::PriceAbsent,
        crate::simulate::SimulateError::SimulateFailed { reason }
        | crate::simulate::SimulateError::SimulateError { reason }
        | crate::simulate::SimulateError::DecodeFailed { reason } => {
            ReflectorError::SimulateFailed { reason }
        }
    })?;

    decode_price_data(&result_scval)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Decodes `(price, timestamp)` from a Reflector `Option<PriceData>` ScVal.
///
/// # ABI provenance
///
/// `Option<PriceData>` per `soroban-env-common/src/option.rs:3-16`:
/// - `ScVal::Void` → `None`.
/// - Raw `PriceData` `ScVal::Map(...)` → `Some(PriceData)`.
///
/// `PriceData` field order (alphabetical per `derive_struct.rs:33` @ `dcbea44`):
/// `price: i128` < `timestamp: u64`.
///
/// i128 reconstruction delegates to [`crate::simulate::decode_i128_scval`].
pub(crate) fn decode_price_data(val: &stellar_xdr::ScVal) -> Result<(i128, u64), ReflectorError> {
    use stellar_xdr::ScVal;

    match val {
        ScVal::Void => Err(ReflectorError::PriceAbsent),
        ScVal::Map(Some(entries)) => {
            let mut maybe_price: Option<i128> = None;
            let mut maybe_timestamp: Option<u64> = None;

            for entry in entries.iter() {
                if let ScVal::Symbol(sym) = &entry.key {
                    if sym.0.as_slice() == b"price" {
                        maybe_price =
                            Some(crate::simulate::decode_i128_scval(&entry.val).map_err(|e| {
                                ReflectorError::DecodeFailed {
                                    reason: format!("price field: {e}"),
                                }
                            })?);
                    } else if sym.0.as_slice() == b"timestamp" {
                        maybe_timestamp = match &entry.val {
                            ScVal::U64(ts) => Some(*ts),
                            other => {
                                return Err(ReflectorError::DecodeFailed {
                                    reason: format!(
                                        "timestamp field is not U64: got {}",
                                        crate::simulate::scval_variant_name(other)
                                    ),
                                });
                            }
                        };
                    }
                }
            }

            let price = maybe_price.ok_or_else(|| ReflectorError::DecodeFailed {
                reason: "price field not found in PriceData map".to_owned(),
            })?;
            let timestamp = maybe_timestamp.ok_or_else(|| ReflectorError::DecodeFailed {
                reason: "timestamp field not found in PriceData map".to_owned(),
            })?;

            // Security: price <= 0 means no valid oracle data.
            if price <= 0 {
                return Err(ReflectorError::PriceAbsent);
            }

            Ok((price, timestamp))
        }
        _ => Err(ReflectorError::DecodeFailed {
            reason: "unexpected PriceData ScVal shape (not Void or Map)".to_owned(),
        }),
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
        reason = "test-only fixture construction"
    )]

    use super::*;

    // ── decode_price_data tests ──────────────────────────────────────────────

    #[test]
    fn decode_void_returns_price_absent() {
        use stellar_xdr::ScVal;
        let result = decode_price_data(&ScVal::Void);
        assert!(matches!(result, Err(ReflectorError::PriceAbsent)));
    }

    #[test]
    fn decode_valid_price_data() {
        use stellar_xdr::{Int128Parts, ScMap, ScMapEntry, ScSymbol, ScVal, StringM, VecM};

        let price_val: i128 = 100_000_000;
        let timestamp_val: u64 = 1_700_000_000;

        let price_sym: StringM<32> = "price".try_into().unwrap();
        let ts_sym: StringM<32> = "timestamp".try_into().unwrap();

        let entries: Vec<ScMapEntry> = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol(price_sym)),
                val: ScVal::I128(Int128Parts {
                    hi: (price_val >> 64) as i64,
                    lo: price_val as u64,
                }),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol(ts_sym)),
                val: ScVal::U64(timestamp_val),
            },
        ];
        let map_vec: VecM<ScMapEntry> = entries.try_into().unwrap();
        let val = ScVal::Map(Some(ScMap(map_vec)));

        let (price, timestamp) = decode_price_data(&val).unwrap();
        assert_eq!(price, price_val);
        assert_eq!(timestamp, timestamp_val);
    }

    #[test]
    fn decode_price_zero_returns_absent() {
        use stellar_xdr::{Int128Parts, ScMap, ScMapEntry, ScSymbol, ScVal, StringM, VecM};

        let price_sym: StringM<32> = "price".try_into().unwrap();
        let ts_sym: StringM<32> = "timestamp".try_into().unwrap();

        let entries: Vec<ScMapEntry> = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol(price_sym)),
                val: ScVal::I128(Int128Parts { hi: 0, lo: 0 }), // price = 0
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol(ts_sym)),
                val: ScVal::U64(1_700_000_000),
            },
        ];
        let map_vec: VecM<ScMapEntry> = entries.try_into().unwrap();
        let val = ScVal::Map(Some(ScMap(map_vec)));

        let result = decode_price_data(&val);
        assert!(
            matches!(result, Err(ReflectorError::PriceAbsent)),
            "price=0 must return PriceAbsent (security: price-zero guard)"
        );
    }

    #[test]
    fn decode_missing_price_field_returns_error() {
        use stellar_xdr::{ScMap, ScMapEntry, ScSymbol, ScVal, StringM, VecM};

        let ts_sym: StringM<32> = "timestamp".try_into().unwrap();
        let entries: Vec<ScMapEntry> = vec![ScMapEntry {
            key: ScVal::Symbol(ScSymbol(ts_sym)),
            val: ScVal::U64(1_700_000_000),
        }];
        let map_vec: VecM<ScMapEntry> = entries.try_into().unwrap();
        let val = ScVal::Map(Some(ScMap(map_vec)));

        let result = decode_price_data(&val);
        assert!(
            matches!(result, Err(ReflectorError::DecodeFailed { .. })),
            "missing price field must return DecodeFailed"
        );
    }

    // ── Error Display audit ──────────────────────────────────────────────────
    //
    // Every ReflectorError variant embeds only the caller-supplied `reason`
    // string (already redacted at the call site) or a fixed message with no
    // address field at all.  The tests below assert the EXACT Display output
    // for all 4 variants so that any future address-bearing field addition
    // would immediately fail the suite.

    #[test]
    fn reflector_error_display_reason_only_no_address_all_variants() {
        // InvalidAddress: "invalid oracle or asset address: {reason}"
        assert_eq!(
            ReflectorError::InvalidAddress {
                reason: "parse failed".to_owned()
            }
            .to_string(),
            "invalid oracle or asset address: parse failed"
        );

        // SimulateFailed: "Reflector lastprice simulate failed: {reason}"
        assert_eq!(
            ReflectorError::SimulateFailed {
                reason: "rpc timeout".to_owned()
            }
            .to_string(),
            "Reflector lastprice simulate failed: rpc timeout"
        );

        // PriceAbsent: fixed message, no address field.
        assert_eq!(
            ReflectorError::PriceAbsent.to_string(),
            "Reflector lastprice returned no result (oracle has no price for this asset)"
        );

        // DecodeFailed: "Reflector PriceData decode failed: {reason}"
        assert_eq!(
            ReflectorError::DecodeFailed {
                reason: "price field not found".to_owned()
            }
            .to_string(),
            "Reflector PriceData decode failed: price field not found"
        );
    }

    // ── Address validation ───────────────────────────────────────────────────

    #[tokio::test]
    async fn invalid_oracle_address_returns_invalid_address() {
        let result = query_reflector_lastprice(
            "not-a-strkey",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "https://soroban-testnet.stellar.org",
            "Test SDF Network ; September 2015",
        )
        .await;
        assert!(
            matches!(result, Err(ReflectorError::InvalidAddress { .. })),
            "invalid oracle address must return InvalidAddress: {result:?}"
        );
    }

    #[tokio::test]
    async fn invalid_asset_address_returns_invalid_address() {
        let result = query_reflector_lastprice(
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "not-a-valid-strkey",
            "https://soroban-testnet.stellar.org",
            "Test SDF Network ; September 2015",
        )
        .await;
        assert!(
            matches!(result, Err(ReflectorError::InvalidAddress { .. })),
            "invalid asset address must return InvalidAddress: {result:?}"
        );
    }

    // ── Wiremock simulate paths ──────────────────────────────────────────────

    const TEST_ORACLE: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
    // A distinct valid C-strkey for the asset address in test fixtures.
    // Same address used as the oracle redaction test address in oracle_staleness tests.
    const TEST_ASSET: &str = "CAZOKR2Y5E2OSWSIBRVZMJ47RUTQPIGVWSAQ2UISGAVC46XKPGDG5PKI";
    const TEST_PASSPHRASE: &str = "Test SDF Network ; September 2015";

    // XDR-base64 for ScVal::Void (discriminant 1, SCV_VOID=1 per stellar-xdr).
    const SCVAL_VOID_B64: &str = "AAAAAQ==";

    // XDR-base64 for ScVal::Map([{Symbol("price"), I128(0,100000000)},
    //   {Symbol("timestamp"), U64(1700000000)}])
    // Generated from stellar-xdr encoding of PriceData fields in alphabetical order
    // per derive_struct.rs:33 @ soroban-sdk dcbea44.
    const PRICE_DATA_MAP_B64: &str = "AAAAEQAAAAEAAAACAAAADwAAAAVwcmljZQAAAAAAAAoAAAAAAAAAAAAAAAAF9eEAAAAADwAAAAl0aW1lc3RhbXAAAAAAAAAFAAAAAGVT8QA=";

    // XDR-base64 for ScVal::Map with price=0 (zero-price guard test).
    const PRICE_DATA_MAP_ZERO_B64: &str = "AAAAEQAAAAEAAAACAAAADwAAAAVwcmljZQAAAAAAAAoAAAAAAAAAAAAAAAAAAAAAAAAADwAAAAl0aW1lc3RhbXAAAAAAAAAFAAAAAGVT8QA=";

    async fn mock_reflector_server(result: serde_json::Value) -> (wiremock::MockServer, String) {
        use stellar_agent_test_support::EchoIdResponder;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(EchoIdResponder::new(result))
            .mount(&server)
            .await;
        let url = server.uri();
        (server, url)
    }

    fn simulate_success_json(xdr_b64: &str) -> serde_json::Value {
        serde_json::json!({
            "latestLedger": 100,
            "minResourceFee": "100",
            "results": [{"auth": [], "xdr": xdr_b64}]
        })
    }

    fn simulate_no_results_json() -> serde_json::Value {
        serde_json::json!({
            "latestLedger": 100,
            "minResourceFee": "100"
        })
    }

    #[tokio::test]
    async fn lastprice_void_returns_price_absent() {
        let (_server, url) = mock_reflector_server(simulate_success_json(SCVAL_VOID_B64)).await;
        let result =
            query_reflector_lastprice(TEST_ORACLE, TEST_ASSET, &url, TEST_PASSPHRASE).await;
        assert!(
            matches!(result, Err(ReflectorError::PriceAbsent)),
            "Void result must return PriceAbsent: {result:?}"
        );
    }

    #[tokio::test]
    async fn lastprice_no_results_returns_price_absent() {
        let (_server, url) = mock_reflector_server(simulate_no_results_json()).await;
        let result =
            query_reflector_lastprice(TEST_ORACLE, TEST_ASSET, &url, TEST_PASSPHRASE).await;
        assert!(
            matches!(result, Err(ReflectorError::PriceAbsent)),
            "no simulate results must return PriceAbsent (via NoResult→PriceAbsent): {result:?}"
        );
    }

    #[tokio::test]
    async fn lastprice_valid_price_data_returns_price_and_timestamp() {
        let (_server, url) = mock_reflector_server(simulate_success_json(PRICE_DATA_MAP_B64)).await;
        let result =
            query_reflector_lastprice(TEST_ORACLE, TEST_ASSET, &url, TEST_PASSPHRASE).await;
        let (price, timestamp) = result.expect("valid PriceData must succeed");
        assert_eq!(price, 100_000_000i128);
        assert_eq!(timestamp, 1_700_000_000u64);
    }

    #[tokio::test]
    async fn lastprice_zero_price_returns_price_absent() {
        let (_server, url) =
            mock_reflector_server(simulate_success_json(PRICE_DATA_MAP_ZERO_B64)).await;
        let result =
            query_reflector_lastprice(TEST_ORACLE, TEST_ASSET, &url, TEST_PASSPHRASE).await;
        assert!(
            matches!(result, Err(ReflectorError::PriceAbsent)),
            "price=0 must return PriceAbsent (security guard): {result:?}"
        );
    }
}
