//! Soroswap router contract-pin data and WASM-hash verification.
//!
//! # What this module does
//!
//! Provides the Soroswap router pins: router address + WASM hash
//! per network, and the [`verify_soroswap_router_wasm`] ordered-trust gate.
//!
//! # Pin provenance (on-chain verified 2026-06-05)
//!
//! ## Testnet
//!
//! Router address: `CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD`
//! Source: `soroswap-core/public/testnet.contracts.json:ids.router`.
//!
//! Router WASM hash: `4b95bbf9caec2c6e00c786f53c5f392c2fcdb8435ac0a862ab5e0645eb65824c`
//! On-chain verified via:
//! `stellar contract fetch --id CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD --network testnet --out-file /tmp/router.wasm`
//! `sha256sum /tmp/router.wasm → 4b95bbf9caec2c6e00c786f53c5f392c2fcdb8435ac0a862ab5e0645eb65824c`
//! (primary RPC: `https://soroban-testnet.stellar.org`).
//!
//! Cross-check: `soroswap-core/public/testnet.contracts.json:hashes.router`
//! = `4b95bbf9caec2c6e00c786f53c5f392c2fcdb8435ac0a862ab5e0645eb65824c`
//! (matches the on-chain fetch).  Only one testnet RPC endpoint was reachable
//! from the dev environment; the two-RPC cross-check runs at sign-time in
//! production against both primary and secondary endpoints.
//!
//! Factory address: `CDP3HMUH6SMS3S7NPGNDJLULCOXXEPSHY4JKUKMBNQMATHDHWXRRJTBY`
//! Source: `soroswap-core/public/testnet.contracts.json:ids.factory`.
//!
//! ABI source: `soroswap-core` (Apache-2.0 / MIT,
//! source `LICENSE` + `package.json:license`; interface-bind only).
//!
//! ## Pubnet
//!
//! Router address: `CAG5LRYQ5JVEUI5TEID72EYOVX44TTUJT5BQR2J6J77FH65PCCFAJDDH`
//! Source: `soroswap-core/public/mainnet.contracts.json:ids.router`.
//!
//! Router WASM hash: `TBD` — pubnet pin verification is deferred (the on-chain
//! acceptance test targets testnet; pubnet verification requires a separate
//! mainnet RPC call at sign-time).
//!
//! # Ordered trust gate
//!
//! The router WASM is pin-verified FIRST (`?`-early-return), before any quote
//! or route state is read from the router.
//!
//! # Behavior
//!
//! Pins the router address and WASM hash per network and pin-verifies the
//! router WASM before any router state is read.

use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_defi::pins::{DefiContractPin, PinVerifyError, verify_pin_for_sign};
use stellar_agent_network::{
    FetchContractWasmHashError, StellarRpcClient, fetch_contract_wasm_hash,
};

// ─────────────────────────────────────────────────────────────────────────────
// WASM hash constants
// ─────────────────────────────────────────────────────────────────────────────

/// Soroswap router WASM hash on testnet.
///
/// On-chain verified 2026-06-05 via
/// `stellar contract fetch --id CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD --network testnet`
/// and sha256sum.
///
/// Matches `soroswap-core/public/testnet.contracts.json:hashes.router`.
/// ABI source: `soroswap-core` (Apache-2.0/MIT).
pub const SOROSWAP_ROUTER_WASM_HASH_TESTNET: [u8; 32] =
    hex_to_bytes(b"4b95bbf9caec2c6e00c786f53c5f392c2fcdb8435ac0a862ab5e0645eb65824c");

/// Soroswap router WASM hash on pubnet.
///
/// All-zeros `TBD` sentinel: `verify_soroswap_router_wasm` refuses any pubnet
/// swap with [`DexPinError::PinNotSet`] until this is set to the on-chain
/// verified hash.  Pubnet verification requires a mainnet RPC call; the
/// on-chain acceptance test targets testnet.
pub const SOROSWAP_ROUTER_WASM_HASH_PUBNET: [u8; 32] = [0u8; 32];

// ─────────────────────────────────────────────────────────────────────────────
// Router address constants
// ─────────────────────────────────────────────────────────────────────────────

/// Soroswap router contract address on testnet.
///
/// Source: `soroswap-core/public/testnet.contracts.json:ids.router`.
pub const SOROSWAP_ROUTER_ADDRESS_TESTNET: &str =
    "CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD";

/// Soroswap router contract address on pubnet.
///
/// Source: `soroswap-core/public/mainnet.contracts.json:ids.router`.
/// NOTE: pubnet WASM hash verification is deferred.
pub const SOROSWAP_ROUTER_ADDRESS_PUBNET: &str =
    "CAG5LRYQ5JVEUI5TEID72EYOVX44TTUJT5BQR2J6J77FH65PCCFAJDDH";

// ─────────────────────────────────────────────────────────────────────────────
// DexPinError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned by the Soroswap pin-verification gate.
///
/// All variants carry non-sensitive diagnostic information.  The `Display`
/// impl never leaks a full contract address or hash.
///
/// # Sibling-variant Display audit
///
/// Every variant is reviewed to ensure its `Display` does not echo full
/// `C…` addresses or hash bytes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DexPinError {
    /// The pin-verify gate failed (WASM hash drift, absent, SAC, or fetch error).
    ///
    /// The inner [`PinVerifyError`] carries full diagnostic context but never
    /// leaks a full address or hash in `Display`.
    #[error("Soroswap router WASM pin-verify failed for {router_redacted}: {inner}")]
    PinVerifyFailed {
        /// Redacted router address (first-5-last-5).
        router_redacted: String,
        /// The underlying pin-verify error.
        inner: PinVerifyError,
    },

    /// The router address is not the expected pinned address for this network.
    #[error(
        "router address {supplied_redacted} is not the pinned Soroswap router \
         for this network (expected {expected_redacted})"
    )]
    RouterAddressMismatch {
        /// Redacted supplied router address.
        supplied_redacted: String,
        /// Redacted expected router address.
        expected_redacted: String,
    },

    /// The router WASM hash pin is all-zeros (TBD sentinel).
    ///
    /// This occurs when [`SOROSWAP_ROUTER_WASM_HASH_PUBNET`] has not been
    /// filled yet.  Refuse until the pin is set.
    #[error(
        "Soroswap router WASM hash pin not yet set for this network \
         (TBD sentinel — verify on-chain and update pins.rs)"
    )]
    PinNotSet,

    /// The network identifier is not recognised.
    #[error("unrecognised network for Soroswap pin selection: {network}")]
    UnrecognisedNetwork {
        /// Network identifier.
        network: String,
    },

    /// The two-RPC WASM-hash fetch failed (network error, invalid address, or divergence).
    #[error("Soroswap router WASM-hash fetch failed for {router_redacted}: {reason}")]
    FetchFailed {
        /// Redacted router address (first-5-last-5).
        router_redacted: String,
        /// Non-sensitive reason (no full address, no RPC internals).
        reason: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// verify_soroswap_router_wasm
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies the Soroswap router WASM hash against the pinned value (two-RPC).
///
/// This is the **first step** of the ordered trust gate (pin-verify-FIRST).
/// No quote, route, or state is read
/// from the router until this returns `Ok(())`.
///
/// # Ordered trust invariant
///
/// ```text
/// verify_soroswap_router_wasm(router_address, network, primary, secondary)?;
/// // Only then: router_get_amounts_out (quote/reverify) and swap submission.
/// ```
///
/// Enforced at the dispatch site by `?`-early-return sequencing.
///
/// # Arguments
///
/// - `router_address` — the router contract address to verify.  Must match the
///   pinned address for the network; mismatches are a hard error.
/// - `network` — `"stellar:testnet"` / `"testnet"` or `"stellar:pubnet"` /
///   `"pubnet"` / `"mainnet"`.
/// - `primary_rpc` — primary Stellar RPC client.
/// - `secondary_rpc` — optional secondary RPC for two-RPC divergence detection.
///   `None` means single-RPC trust (permitted only when the profile has no
///   secondary endpoint configured).
///
/// # Errors
///
/// Returns [`DexPinError`] when:
/// - The supplied router address does not match the pinned address for the network.
/// - The pin sentinel is all-zeros (pubnet TBD).
/// - The WASM-hash fetch fails (network error, invalid address, or divergence).
/// - The on-chain WASM hash does not match the pin.
pub async fn verify_soroswap_router_wasm(
    router_address: &str,
    network: &str,
    primary_rpc: &StellarRpcClient,
    secondary_rpc: Option<&StellarRpcClient>,
) -> Result<(), DexPinError> {
    let (expected_address, expected_hash) = pinned_router_for_network(network)?;

    // Guard: all-zeros hash = TBD sentinel, refuse immediately.
    if expected_hash == [0u8; 32] {
        return Err(DexPinError::PinNotSet);
    }

    // Guard: supplied address must match the pinned address.
    if router_address != expected_address {
        return Err(DexPinError::RouterAddressMismatch {
            supplied_redacted: redact_strkey_first5_last5(router_address),
            expected_redacted: redact_strkey_first5_last5(expected_address),
        });
    }

    // Two-RPC WASM-hash fetch.
    let fetch_result = fetch_contract_wasm_hash(primary_rpc, secondary_rpc, router_address).await;

    let wasm_fetch = match fetch_result {
        Ok(f) => f,
        Err(FetchContractWasmHashError::InvalidAddress { reason, .. }) => {
            return Err(DexPinError::FetchFailed {
                router_redacted: redact_strkey_first5_last5(router_address),
                reason: format!("invalid address: {reason}"),
            });
        }
        Err(FetchContractWasmHashError::Unavailable { .. }) => {
            return Err(DexPinError::FetchFailed {
                router_redacted: redact_strkey_first5_last5(router_address),
                reason: "RPC fetch unavailable".to_owned(),
            });
        }
        Err(FetchContractWasmHashError::Divergent(e)) => {
            return Err(DexPinError::FetchFailed {
                router_redacted: redact_strkey_first5_last5(router_address),
                reason: format!(
                    "two-RPC divergence: primary={} secondary={}",
                    e.primary_first8, e.secondary_first8
                ),
            });
        }
        // #[non_exhaustive] — fail-closed on any unknown variant.
        Err(_) => {
            return Err(DexPinError::FetchFailed {
                router_redacted: redact_strkey_first5_last5(router_address),
                reason: "unknown fetch error".to_owned(),
            });
        }
    };

    // Build a DefiContractPin from the static pinned values and verify.
    // `DefiContractPin::new` is used because `#[non_exhaustive]` prevents
    // struct-literal construction outside the defining crate.
    let pin = DefiContractPin::new(
        "soroswap",      // protocol
        "router-direct", // version
        "default",       // profile
        network,         // network passphrase / identifier
        router_address,  // contract_address (C-strkey)
        expected_hash,   // pinned wasm_hash [u8; 32]
        "soroswap-core", // abi_source_provenance
    );

    verify_pin_for_sign(&pin, &wasm_fetch).map_err(|inner| DexPinError::PinVerifyFailed {
        router_redacted: redact_strkey_first5_last5(router_address),
        inner,
    })
}

/// Returns `(address, wasm_hash)` for the pinned Soroswap router on `network`.
///
/// # Errors
///
/// Returns [`DexPinError::UnrecognisedNetwork`] when `network` is not
/// `"stellar:testnet"`, `"testnet"`, `"stellar:pubnet"`, `"pubnet"`, or `"mainnet"`.
pub fn pinned_router_for_network(network: &str) -> Result<(&'static str, [u8; 32]), DexPinError> {
    match network {
        "stellar:testnet" | "testnet" => Ok((
            SOROSWAP_ROUTER_ADDRESS_TESTNET,
            SOROSWAP_ROUTER_WASM_HASH_TESTNET,
        )),
        "stellar:pubnet" | "pubnet" | "mainnet" => Ok((
            SOROSWAP_ROUTER_ADDRESS_PUBNET,
            SOROSWAP_ROUTER_WASM_HASH_PUBNET,
        )),
        other => Err(DexPinError::UnrecognisedNetwork {
            network: other.to_owned(),
        }),
    }
}

/// Returns the Stellar network passphrase for a CAIP-2 / shorthand network id.
///
/// Accepts the same identifiers as [`pinned_router_for_network`].  The passphrase
/// values are the canonical constants from `stellar-agent-core`.
///
/// SAC canonicalisation derives contract ids from the network PASSPHRASE, so the
/// preview path uses this to map its CAIP-2 chain id to the passphrase when no
/// submit-context passphrase is supplied.
///
/// # Errors
///
/// Returns [`DexPinError::UnrecognisedNetwork`] when `network` is not
/// `"stellar:testnet"`, `"testnet"`, `"stellar:pubnet"`, `"pubnet"`, or
/// `"mainnet"`.
pub fn passphrase_for_network(network: &str) -> Result<&'static str, DexPinError> {
    match network {
        "stellar:testnet" | "testnet" => Ok(stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE),
        "stellar:pubnet" | "pubnet" | "mainnet" => {
            Ok(stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE)
        }
        other => Err(DexPinError::UnrecognisedNetwork {
            network: other.to_owned(),
        }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time hex decoder
// ─────────────────────────────────────────────────────────────────────────────

/// Converts a 64-byte ASCII hex literal to a `[u8; 32]` at compile time.
///
/// Panics at compile time on non-hex input.
const fn hex_to_bytes(hex: &[u8]) -> [u8; 32] {
    assert!(hex.len() == 64, "hex string must be exactly 64 bytes");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let hi = hex_nibble(hex[i * 2]);
        let lo = hex_nibble(hex[i * 2 + 1]);
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    out
}

#[allow(clippy::panic)]
// SAFETY: only called with compile-time hex string literals; the panic can
// never trigger at runtime.
const fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("invalid hex nibble — only called with compile-time literals"),
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

    #[test]
    fn testnet_wasm_hash_is_correct_length() {
        assert_eq!(SOROSWAP_ROUTER_WASM_HASH_TESTNET.len(), 32);
        // Must not be all-zeros (TBD sentinel).
        assert_ne!(
            SOROSWAP_ROUTER_WASM_HASH_TESTNET, [0u8; 32],
            "testnet WASM hash must not be the TBD sentinel"
        );
    }

    #[test]
    fn testnet_hash_bytes_match_known_answer() {
        // On-chain verified 2026-06-05: sha256sum of WASM fetched via
        // `stellar contract fetch --id CCJUD55... --network testnet`
        // = 4b95bbf9caec2c6e00c786f53c5f392c2fcdb8435ac0a862ab5e0645eb65824c
        //
        // Compare bytes directly — no external hex-encode dependency.
        let expected: [u8; 32] = [
            0x4b, 0x95, 0xbb, 0xf9, 0xca, 0xec, 0x2c, 0x6e, 0x00, 0xc7, 0x86, 0xf5, 0x3c, 0x5f,
            0x39, 0x2c, 0x2f, 0xcd, 0xb8, 0x43, 0x5a, 0xc0, 0xa8, 0x62, 0xab, 0x5e, 0x06, 0x45,
            0xeb, 0x65, 0x82, 0x4c,
        ];
        assert_eq!(
            SOROSWAP_ROUTER_WASM_HASH_TESTNET, expected,
            "testnet WASM hash must match the on-chain verified value"
        );
    }

    #[test]
    fn pubnet_hash_is_tbd_sentinel() {
        // Pubnet hash is all-zeros until the on-chain verification is done.
        assert_eq!(
            SOROSWAP_ROUTER_WASM_HASH_PUBNET, [0u8; 32],
            "pubnet WASM hash must be TBD sentinel until verified"
        );
    }

    #[test]
    fn pinned_router_for_testnet_returns_expected_values() {
        let (addr, hash) = pinned_router_for_network("stellar:testnet").unwrap();
        assert_eq!(addr, SOROSWAP_ROUTER_ADDRESS_TESTNET);
        assert_eq!(hash, SOROSWAP_ROUTER_WASM_HASH_TESTNET);
    }

    #[test]
    fn pinned_router_testnet_alt_key() {
        let (addr, _) = pinned_router_for_network("testnet").unwrap();
        assert_eq!(addr, SOROSWAP_ROUTER_ADDRESS_TESTNET);
    }

    #[test]
    fn pinned_router_pubnet_returns_expected_address() {
        let (addr, hash) = pinned_router_for_network("stellar:pubnet").unwrap();
        assert_eq!(addr, SOROSWAP_ROUTER_ADDRESS_PUBNET);
        // Pubnet hash is TBD sentinel.
        assert_eq!(hash, [0u8; 32]);
    }

    #[test]
    fn pinned_router_addresses_are_valid_c_strkeys() {
        // Both pinned router addresses must parse as Stellar contract C-strkeys,
        // so a malformed pin can never be committed.
        assert!(
            stellar_strkey::Contract::from_string(SOROSWAP_ROUTER_ADDRESS_TESTNET).is_ok(),
            "testnet router pin must be a valid C-strkey"
        );
        assert!(
            stellar_strkey::Contract::from_string(SOROSWAP_ROUTER_ADDRESS_PUBNET).is_ok(),
            "pubnet router pin must be a valid C-strkey"
        );
    }

    #[test]
    fn pinned_router_unrecognised_network_errors() {
        let result = pinned_router_for_network("stellar:futurenet");
        assert!(matches!(
            result,
            Err(DexPinError::UnrecognisedNetwork { .. })
        ));
    }

    #[test]
    fn passphrase_for_network_resolves_canonical_passphrases() {
        assert_eq!(
            passphrase_for_network("stellar:testnet").unwrap(),
            "Test SDF Network ; September 2015"
        );
        assert_eq!(
            passphrase_for_network("testnet").unwrap(),
            "Test SDF Network ; September 2015"
        );
        assert_eq!(
            passphrase_for_network("stellar:pubnet").unwrap(),
            "Public Global Stellar Network ; September 2015"
        );
        assert_eq!(
            passphrase_for_network("mainnet").unwrap(),
            "Public Global Stellar Network ; September 2015"
        );
        assert!(matches!(
            passphrase_for_network("stellar:futurenet"),
            Err(DexPinError::UnrecognisedNetwork { .. })
        ));
    }

    #[test]
    fn testnet_passphrase_canonicalises_native_to_known_xlm_sac() {
        // The passphrase returned for the testnet id must canonicalise `native`
        // to the known-answer XLM SAC — i.e. preview() must feed this, not the
        // CAIP-2 id, into SAC canonicalisation.
        let passphrase = passphrase_for_network("stellar:testnet").unwrap();
        let sac = crate::sac::canonicalise_token("native", passphrase).unwrap();
        assert_eq!(
            sac,
            "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC"
        );
    }

    #[test]
    fn caip2_id_used_as_passphrase_yields_wrong_sac() {
        // Regression guard: using the CAIP-2 id ("stellar:testnet") as the
        // passphrase derives a DIFFERENT, non-existent SAC. preview() must not
        // do this.
        let wrong = crate::sac::canonicalise_token("native", "stellar:testnet").unwrap();
        assert_ne!(
            wrong, "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
            "CAIP-2 id must NOT canonicalise native to the testnet XLM SAC"
        );
    }

    #[tokio::test]
    async fn verify_router_wasm_pubnet_returns_pin_not_set() {
        // The pubnet WASM hash is the all-zeros TBD sentinel, so verification
        // refuses with PinNotSet BEFORE any RPC call (the dummy client is never
        // contacted).
        let dummy = StellarRpcClient::new("http://localhost:1").expect("client constructs");
        let result = verify_soroswap_router_wasm(
            SOROSWAP_ROUTER_ADDRESS_PUBNET,
            "stellar:pubnet",
            &dummy,
            None,
        )
        .await;
        assert!(matches!(result, Err(DexPinError::PinNotSet)));
    }

    #[tokio::test]
    async fn verify_router_wasm_testnet_address_mismatch() {
        // A router address that differs from the pinned testnet router is refused
        // with RouterAddressMismatch BEFORE any RPC call (the testnet hash is
        // set, so the PinNotSet guard does not trigger).
        let dummy = StellarRpcClient::new("http://localhost:1").expect("client constructs");
        let result = verify_soroswap_router_wasm(
            "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
            "stellar:testnet",
            &dummy,
            None,
        )
        .await;
        assert!(matches!(
            result,
            Err(DexPinError::RouterAddressMismatch { .. })
        ));
    }

    #[test]
    fn error_display_no_full_address_leak() {
        let full_addr = SOROSWAP_ROUTER_ADDRESS_TESTNET;
        let err = DexPinError::RouterAddressMismatch {
            supplied_redacted: redact_strkey_first5_last5(full_addr),
            expected_redacted: redact_strkey_first5_last5(full_addr),
        };
        let display = err.to_string();
        // Full 56-char address must not appear in the error message.
        assert!(
            !display.contains(full_addr),
            "error display must not contain full address"
        );
    }

    #[test]
    fn fetch_failed_display_no_full_address_leak() {
        let full_addr = SOROSWAP_ROUTER_ADDRESS_TESTNET;
        let err = DexPinError::FetchFailed {
            router_redacted: redact_strkey_first5_last5(full_addr),
            reason: "RPC fetch unavailable".to_owned(),
        };
        let display = err.to_string();
        assert!(
            !display.contains(full_addr),
            "FetchFailed display must not contain full address"
        );
    }

    #[test]
    fn hex_to_bytes_endpoints() {
        // Spot-check the compile-time decoder's first and last bytes; the full
        // value is covered by `testnet_hash_bytes_match_known_answer`.
        let hash = SOROSWAP_ROUTER_WASM_HASH_TESTNET;
        assert_eq!(hash[0], 0x4b, "first byte must be 0x4b");
        assert_eq!(hash[31], 0x4c, "last byte must be 0x4c");
    }
}
