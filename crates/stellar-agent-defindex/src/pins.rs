//! DeFindex contract WASM hash pins and factory addresses.
//!
//! # Pin provenance (re-verified on-chain 2026-06-04)
//!
//! ## Authoritative source for vault WASM hash
//!
//! The canonical DeFindex vault WASM hash is `f345228d…016be`, confirmed by:
//! 1. `public/testnet.contracts.json` `hashes.defindex_vault` (root-level file in
//!    the DeFindex contracts repository) — this is the hash deployed on testnet.
//! 2. On-chain verification: `stellar contract invoke --id CDSCWE4GLNBYYTES2OCYDFQA2LLY4RBIAX6ZI32VSUXD7GO6HRPO4A32 \
//!    --network testnet -- vault_wasm_hash` returns
//!    `"f345228dca59c6605789620e9ec62ff4847a0927c33dac7581a955fe746016be"` (factory-blessed).
//! 3. `stellar contract fetch --id CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN \
//!    --network testnet` confirms the vault binary matches.
//!
//! The `apps/contracts/public/testnet.contracts.json` (subdirectory) contained an OLDER
//! pre-deployment hash `0f3073…f3a` that does NOT match the live vault.  The root-level
//! `public/testnet.contracts.json` is the correct source for live testnet pins.
//!
//! ## Testnet
//!
//! Source: `public/testnet.contracts.json` (root-level in the DeFindex contracts repository clone).
//!
//! Vault factory address: `CDSCWE4GLNBYYTES2OCYDFQA2LLY4RBIAX6ZI32VSUXD7GO6HRPO4A32`
//! (from `public/testnet.contracts.json` `ids.defindex_factory`).
//!
//! | Contract         | WASM hash (hex)                                                          |
//! |------------------|--------------------------------------------------------------------------|
//! | `defindex_vault` | `f345228dca59c6605789620e9ec62ff4847a0927c33dac7581a955fe746016be` |
//! | `defindex_factory` | `baba1e5e12e7f83b49f6f2b6b17f7bc672e38c08dca74f77d66d569c522cfec8` |
//! | `blend_strategy` | `0b1f49e25e7863f06acbf5d18caf82c9ad4140a46521e209221a08aa8940a6a1` |
//!
//! Testnet vault addresses (for acceptance tests):
//! - `usdc_paltalabs_vault`: `CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN`
//!   (from `public/testnet.contracts.json` `ids.usdc_paltalabs_vault`)
//!
//! ## Pubnet
//!
//! Pubnet pins are TBD (not yet verified on-chain; set conservatively to
//! the same hash as testnet — re-verify at pubnet launch).
//!
//! ## ABI note: GPL-3.0
//!
//! DeFindex contracts are GPL-3.0.
//! This crate binds the interface only (no source vendored), which keeps the
//! GPL boundary clear.

use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_network::{StellarRpcClient, WasmHashFetch, fetch_contract_wasm_hash};

// ─────────────────────────────────────────────────────────────────────────────
// Vault WASM hash constants (same hash on both networks as of 2026-06-04)
// ─────────────────────────────────────────────────────────────────────────────

/// DeFindex vault WASM hash — factory-blessed, on-chain verified 2026-06-04.
///
/// Source: `public/testnet.contracts.json` `hashes.defindex_vault` in
/// the DeFindex contracts repository (root-level; NOT `apps/contracts/public/`).
/// Confirmed by `stellar contract invoke -- vault_wasm_hash` against the
/// testnet factory `CDSCWE4GLNBYYTES2OCYDFQA2LLY4RBIAX6ZI32VSUXD7GO6HRPO4A32`.
/// On-chain result: `"f345228dca59c6605789620e9ec62ff4847a0927c33dac7581a955fe746016be"`.
pub const DEFINDEX_VAULT_WASM_HASH: [u8; 32] =
    hex_to_bytes(b"f345228dca59c6605789620e9ec62ff4847a0927c33dac7581a955fe746016be");

/// DeFindex factory WASM hash — testnet, verified 2026-06-04.
///
/// Source: `public/testnet.contracts.json` `hashes.defindex_factory`.
pub const DEFINDEX_FACTORY_WASM_HASH: [u8; 32] =
    hex_to_bytes(b"baba1e5e12e7f83b49f6f2b6b17f7bc672e38c08dca74f77d66d569c522cfec8");

// ─────────────────────────────────────────────────────────────────────────────
// Blend strategy WASM hash constants (network-specific)
// ─────────────────────────────────────────────────────────────────────────────

/// DeFindex Blend strategy WASM hash on testnet.
///
/// Source: `public/testnet.contracts.json` `hashes.blend_strategy`
/// (root-level in the DeFindex contracts repository). Verified 2026-06-04.
///
/// Used for Blend-strategy detection via WASM-hash match.
/// The strategy `name` field is caller-supplied/untrusted and MUST NOT be
/// used for detection.  Only WASM-hash match is authoritative.
pub const BLEND_STRATEGY_WASM_HASH_TESTNET: [u8; 32] =
    hex_to_bytes(b"0b1f49e25e7863f06acbf5d18caf82c9ad4140a46521e209221a08aa8940a6a1");

/// DeFindex Blend strategy WASM hash on pubnet.
///
/// Source: `apps/contracts/public/mainnet.contracts.json`
/// `hashes.blend_strategy` (the DeFindex contracts repository).
/// Verified 2026-06-04 against `apps/contracts/public/mainnet.contracts.json`.
///
/// Used for Blend-strategy detection via WASM-hash match.
pub const BLEND_STRATEGY_WASM_HASH_PUBNET: [u8; 32] =
    hex_to_bytes(b"11329c2469455f5a3815af1383c0cdddb69215b1668a17ef097516cde85da988");

// ─────────────────────────────────────────────────────────────────────────────
// verify_defindex_vault_wasm
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies a DeFindex vault's on-chain WASM hash against the pinned hash
/// using a two-RPC cross-check.
///
/// This is **step 1** of the ordered trust gate (pin-verify → read Upgradable
/// → read roles → read assets), which must complete before any vault storage
/// value is consumed (ordered trust invariant).
///
/// The `secondary_rpc` is threaded at the gate call site, NOT via
/// `DefiAdapterCtx` which carries only a single `primary_rpc`.
///
/// # Errors
///
/// Returns [`DefindexPinError`] when:
/// - The vault address is invalid.
/// - The on-chain WASM hash does not match the pinned hash (Drift).
/// - The vault is a SAC or absent (fail-closed by type).
/// - The primary or secondary RPC is unavailable.
/// - Primary and secondary RPC disagree (Divergent).
pub async fn verify_defindex_vault_wasm(
    vault_address: &str,
    primary_rpc: &StellarRpcClient,
    secondary_rpc: Option<&StellarRpcClient>,
) -> Result<(), DefindexPinError> {
    let fetch = fetch_contract_wasm_hash(primary_rpc, secondary_rpc, vault_address)
        .await
        .map_err(|e| DefindexPinError::FetchFailed {
            reason: format!("{e}"),
        })?;

    match fetch {
        WasmHashFetch::Wasm(on_chain_hash) => {
            if on_chain_hash == DEFINDEX_VAULT_WASM_HASH {
                Ok(())
            } else {
                let first8: String = on_chain_hash[..8]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                Err(DefindexPinError::HashMismatch {
                    vault_redacted: redact_strkey_first5_last5(vault_address),
                    on_chain_first8: first8,
                })
            }
        }
        WasmHashFetch::Sac => Err(DefindexPinError::SacNotVault {
            vault_redacted: redact_strkey_first5_last5(vault_address),
        }),
        WasmHashFetch::Absent => Err(DefindexPinError::Absent {
            vault_redacted: redact_strkey_first5_last5(vault_address),
        }),
        // #[non_exhaustive]: any future WasmHashFetch variants are also refused.
        _ => Err(DefindexPinError::FetchFailed {
            reason: "unexpected WasmHashFetch variant (future extension)".to_owned(),
        }),
    }
}

/// Returns `true` if the strategy WASM hash matches the pinned Blend strategy
/// hash for `network`.
///
/// # Blend-strategy detection
///
/// Detection MUST use WASM-hash match only.  The strategy `name` field is
/// caller-supplied and untrusted; it MUST NOT be used for detection.
///
/// The returned bool is used to set [`crate::abi::WalletStrategy::is_blend_strategy`].
#[must_use]
pub fn is_blend_strategy(strategy_wasm_hash: &[u8; 32], network: &str) -> bool {
    let pinned = match network {
        "pubnet" | "stellar:pubnet" | "Public Global Stellar Network ; September 2015" => {
            &BLEND_STRATEGY_WASM_HASH_PUBNET
        }
        _ => &BLEND_STRATEGY_WASM_HASH_TESTNET,
    };
    strategy_wasm_hash == pinned
}

// ─────────────────────────────────────────────────────────────────────────────
// DefindexPinError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned by [`verify_defindex_vault_wasm`].
///
/// All `Display` outputs carry only first-5-last-5 redacted addresses and
/// first-8-hex hashes; full hashes and addresses NEVER appear.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DefindexPinError {
    /// The on-chain WASM hash does not match the pinned DeFindex vault hash.
    #[error("DeFindex vault WASM hash mismatch for {vault_redacted}: on-chain={on_chain_first8}")]
    HashMismatch {
        /// First-5-last-5 redacted vault address.
        vault_redacted: String,
        /// First-8 hex of the on-chain hash.
        on_chain_first8: String,
    },

    /// The contract is a Stellar Asset Contract, not a DeFindex vault.
    #[error("address {vault_redacted} is a SAC, not a DeFindex vault")]
    SacNotVault {
        /// First-5-last-5 redacted address.
        vault_redacted: String,
    },

    /// The contract address is absent from the ledger.
    #[error("DeFindex vault {vault_redacted} is absent from the ledger")]
    Absent {
        /// First-5-last-5 redacted address.
        vault_redacted: String,
    },

    /// The WASM-hash fetch failed (RPC unavailable or divergent).
    #[error("DeFindex vault WASM-hash fetch failed: {reason}")]
    FetchFailed {
        /// Non-sensitive reason string.
        reason: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Const hex decoder (shared with blend/pins.rs; internal copy)
// ─────────────────────────────────────────────────────────────────────────────

#[allow(clippy::panic)]
// SAFETY: This const fn is only called with compile-time hex string literals;
// the panic can never trigger at runtime.
const fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("invalid hex nibble — only called with compile-time literals"),
    }
}

const fn hex_to_bytes(hex: &[u8]) -> [u8; 32] {
    assert!(hex.len() == 64, "expected 64 hex chars for 32 bytes");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (hex_nibble(hex[i * 2]) << 4) | hex_nibble(hex[i * 2 + 1]);
        i += 1;
    }
    out
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

    // ── WASM hash constants are correct hex ──────────────────────────────────

    #[test]
    fn vault_wasm_hash_matches_expected_hex() {
        // Factory-blessed hash: verified on-chain via `vault_wasm_hash()` view
        // against testnet factory CDSCWE4GLNBYYTES2OCYDFQA2LLY4RBIAX6ZI32VSUXD7GO6HRPO4A32.
        let expected_hex = "f345228dca59c6605789620e9ec62ff4847a0927c33dac7581a955fe746016be";
        let mut expected = [0u8; 32];
        for (i, b) in expected.iter_mut().enumerate() {
            let hi = u8::from_str_radix(&expected_hex[i * 2..i * 2 + 1], 16).unwrap();
            let lo = u8::from_str_radix(&expected_hex[i * 2 + 1..i * 2 + 2], 16).unwrap();
            *b = (hi << 4) | lo;
        }
        assert_eq!(DEFINDEX_VAULT_WASM_HASH, expected);
    }

    #[test]
    fn factory_wasm_hash_matches_expected_hex() {
        // Source: public/testnet.contracts.json hashes.defindex_factory (root-level).
        let expected_hex = "baba1e5e12e7f83b49f6f2b6b17f7bc672e38c08dca74f77d66d569c522cfec8";
        let mut expected = [0u8; 32];
        for (i, b) in expected.iter_mut().enumerate() {
            let hi = u8::from_str_radix(&expected_hex[i * 2..i * 2 + 1], 16).unwrap();
            let lo = u8::from_str_radix(&expected_hex[i * 2 + 1..i * 2 + 2], 16).unwrap();
            *b = (hi << 4) | lo;
        }
        assert_eq!(DEFINDEX_FACTORY_WASM_HASH, expected);
    }

    // ── Blend-strategy detection ─────────────────────────────────────────────

    #[test]
    fn blend_strategy_detected_on_testnet() {
        assert!(is_blend_strategy(
            &BLEND_STRATEGY_WASM_HASH_TESTNET,
            "testnet"
        ));
    }

    #[test]
    fn blend_strategy_detected_on_pubnet() {
        assert!(is_blend_strategy(
            &BLEND_STRATEGY_WASM_HASH_PUBNET,
            "pubnet"
        ));
    }

    #[test]
    fn testnet_blend_hash_not_detected_as_pubnet_blend() {
        // Hashes differ between testnet and pubnet for blend_strategy.
        // Testnet: 0b1f49e2…, pubnet: 11329c24…
        assert!(
            !is_blend_strategy(&BLEND_STRATEGY_WASM_HASH_TESTNET, "pubnet"),
            "testnet blend hash must not match pubnet"
        );
    }

    #[test]
    fn pubnet_blend_hash_not_detected_as_testnet_blend() {
        assert!(
            !is_blend_strategy(&BLEND_STRATEGY_WASM_HASH_PUBNET, "testnet"),
            "pubnet blend hash must not match testnet"
        );
    }

    #[test]
    fn random_hash_is_not_blend_strategy() {
        let random_hash = [0u8; 32];
        assert!(!is_blend_strategy(&random_hash, "testnet"));
        assert!(!is_blend_strategy(&random_hash, "pubnet"));
    }

    // ── DefindexPinError Display redacts addresses ────────────────────────────

    #[test]
    fn hash_mismatch_display_shows_only_first8() {
        let err = DefindexPinError::HashMismatch {
            vault_redacted: "CBMVK…ZDWHN".to_owned(),
            on_chain_first8: "f345228d".to_owned(),
        };
        let display = err.to_string();
        // Must show first-8 hash
        assert!(display.contains("f345228d"), "must show first-8 hash");
        // Must NOT show full hash
        assert!(
            !display.contains("f345228dca59c6605789620e9ec62ff4847a0927c33dac7581a955fe746016be"),
            "must not show full hash"
        );
    }
}
