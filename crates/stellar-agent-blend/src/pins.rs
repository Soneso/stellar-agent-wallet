//! Blend-specific contract-pin data and pool-WASM set.
//!
//! # What this module does
//!
//! Provides the contract-pin data for the Blend protocol: v1+v2 pool
//! WASM hashes per network, factory/backstop/oracle addresses, and the
//! Reflector oracle allowlist.
//!
//! The per-network `blend_pool_wasm_set_*` functions return the set of valid pool WASM hashes
//! for a given network, used with [`verify_blend_pool_wasm`] (which accepts any
//! hash matching the set — a single Blend pool may be v1 or v2) via the
//! `stellar_agent_network::fetch_contract_wasm_hash` two-RPC primitive.
//!
//! # Pin provenance (re-verified on-chain 2026-06-04)
//!
//! ## Testnet
//!
//! v2 pool address: `CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF`
//! (from `blend-capital/blend-utils` `testnet.contracts.json` `ids.TestnetV2`).
//!
//! v2 pool WASM hash: `a41fc53d6753b6c04eb15b021c55052366a4c8e0e21bc72700f461264ec1350e`
//! (from `blend-capital/blend-utils` `testnet.contracts.json` `hashes.lendingPoolV2`
//! and on-chain verified via `stellar contract fetch --id CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF --network testnet` + sha256sum).
//!
//! v1 pool: no v1 pool is deployed on the current Blend testnet environment
//! (Blend testnet runs v2); v1 hash is present for completeness from mainnet.
//!
//! Testnet oracle: `CAZOKR2Y5E2OSWSIBRVZMJ47RUTQPIGVWSAQ2UISGAVC46XKPGDG5PKI`
//! (oracle mock used by `CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF`,
//! from testnet.contracts.json `oraclemock`, confirmed via `stellar contract invoke ... -- get_config`).
//!
//! ## Pubnet
//!
//! v1 pool WASM hash: `baf978f10efdbcd85747868bef8832845ea6809f7643b67a4ac0cd669327fc2c`
//! (from `blend-capital/blend-utils` `mainnet.contracts.json` `hashes.lendingPool`
//! and on-chain verified: `stellar contract fetch --id CDVQVKOY2YSXS2IC7KN6MNASSHPAO7UN2UR2ON4OI2SKMFJNVAMDX6DP --rpc-url https://rpc.ankr.com/stellar_soroban ...` + sha256sum).
//!
//! v2 pool WASM hash: `a41fc53d6753b6c04eb15b021c55052366a4c8e0e21bc72700f461264ec1350e`
//! (from `blend-capital/blend-utils` `mainnet.contracts.json`; on-chain verified:
//! `stellar contract fetch --id CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD --rpc-url https://rpc.ankr.com/stellar_soroban ...` + sha256sum = same hash).
//!
//! Pubnet oracle (Reflector Pulse): `CCVTVW2CVA7JLH4ROQGP3CU4T3EXVCK66AZGSM4MUQPXAI4QHCZPOATS`
//! Verified SEP-40 compliant: `stellar contract invoke ... -- lastprice --asset '{"Stellar": "CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75"}'`
//! → `{"price":"10008096","timestamp":1780572600}` (2026-06-04).
//!
//! ABI source provenance (v1): `blend-contracts`.
//! ABI source provenance (v2): `blend-contracts-v2`.
//!
//! Pins both the v1 and v2 pool WASM hashes per network.

use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_network::{StellarRpcClient, WasmHashFetch, fetch_contract_wasm_hash};

// ─────────────────────────────────────────────────────────────────────────────
// WASM hash constants (per network, per version)
// ─────────────────────────────────────────────────────────────────────────────

/// Blend v1 pool WASM hash on pubnet.
///
/// On-chain verified 2026-06-04 via
/// `stellar contract fetch --id CDVQVKOY2YSXS2IC7KN6MNASSHPAO7UN2UR2ON4OI2SKMFJNVAMDX6DP`.
/// Source: `blend-capital/blend-utils mainnet.contracts.json hashes.lendingPool`.
pub const BLEND_V1_POOL_WASM_HASH_PUBNET: [u8; 32] =
    hex_to_bytes(b"baf978f10efdbcd85747868bef8832845ea6809f7643b67a4ac0cd669327fc2c");

/// Blend v2 pool WASM hash on pubnet.
///
/// On-chain verified 2026-06-04 via
/// `stellar contract fetch --id CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD`.
/// Source: `blend-capital/blend-utils mainnet.contracts.json hashes.lendingPoolV2`.
/// Also matches: `stellar contract fetch --id CCCCIQSDILITHMM7PBSLVDT5MISSY7R26MNZXCX4H7J5JQ5FPIYOGYFS`.
pub const BLEND_V2_POOL_WASM_HASH_PUBNET: [u8; 32] =
    hex_to_bytes(b"a41fc53d6753b6c04eb15b021c55052366a4c8e0e21bc72700f461264ec1350e");

/// Blend v2 pool WASM hash on testnet (same as pubnet v2 — same compiled WASM).
///
/// On-chain verified 2026-06-04 via
/// `stellar contract fetch --id CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF --network testnet` + sha256sum.
/// Source: `blend-capital/blend-utils testnet.contracts.json hashes.lendingPoolV2`.
pub const BLEND_V2_POOL_WASM_HASH_TESTNET: [u8; 32] =
    hex_to_bytes(b"a41fc53d6753b6c04eb15b021c55052366a4c8e0e21bc72700f461264ec1350e");

// ─────────────────────────────────────────────────────────────────────────────
// Reflector oracle allowlist (single source of truth)
// ─────────────────────────────────────────────────────────────────────────────

/// Reflector oracle allowlist for the pubnet network.
///
/// A Blend pool whose `PoolConfig.oracle` is NOT in this list is refused
/// regardless of simulate result.
///
/// Address verified as SEP-40 compliant on 2026-06-04 via
/// `stellar contract invoke ... -- lastprice --asset '{"Stellar": "CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75"}'`
/// → `{"price":"10008096","timestamp":1780572600}` (Reflector Pulse).
/// Both mainnet Blend v2 pools (`CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD`
/// and `CCCCIQSDILITHMM7PBSLVDT5MISSY7R26MNZXCX4H7J5JQ5FPIYOGYFS`) report oracle
/// `CCVTVW2CVA7JLH4ROQGP3CU4T3EXVCK66AZGSM4MUQPXAI4QHCZPOATS` via `get_config`.
pub const REFLECTOR_ORACLE_ALLOWLIST_PUBNET: &[&str] =
    &["CCVTVW2CVA7JLH4ROQGP3CU4T3EXVCK66AZGSM4MUQPXAI4QHCZPOATS"];

/// Reflector oracle allowlist for the testnet network.
///
/// The current testnet Blend v2 pool uses an oracle mock at
/// `CAZOKR2Y5E2OSWSIBRVZMJ47RUTQPIGVWSAQ2UISGAVC46XKPGDG5PKI`
/// (confirmed via `stellar contract invoke --id CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF --network testnet -- get_config`).
/// For testnet acceptance tests, this oracle mock is the allowed oracle.
pub const REFLECTOR_ORACLE_ALLOWLIST_TESTNET: &[&str] =
    &["CAZOKR2Y5E2OSWSIBRVZMJ47RUTQPIGVWSAQ2UISGAVC46XKPGDG5PKI"];

// ─────────────────────────────────────────────────────────────────────────────
// Pool WASM sets
// ─────────────────────────────────────────────────────────────────────────────

/// A set of valid Blend pool WASM hashes for a single network.
///
/// A pool whose on-chain WASM hash matches ANY entry is accepted as a known
/// Blend pool.  Non-matches are refused by [`verify_blend_pool_wasm`].
#[derive(Clone, Debug)]
pub struct BlendPoolWasmSet {
    /// All valid pool WASM hashes for this network (v1 + v2).
    pub hashes: &'static [[u8; 32]],
    /// Human-readable network label for error messages.
    pub network: &'static str,
}

/// Returns the Blend pool WASM set for the pubnet network.
///
/// Includes both v1 (`baf978f1…`) and v2 (`a41fc53d…`) hashes.
#[must_use]
pub fn blend_pool_wasm_set_pubnet() -> BlendPoolWasmSet {
    static HASHES: [[u8; 32]; 2] = [
        BLEND_V1_POOL_WASM_HASH_PUBNET,
        BLEND_V2_POOL_WASM_HASH_PUBNET,
    ];
    BlendPoolWasmSet {
        hashes: &HASHES,
        network: "pubnet",
    }
}

/// Returns the Blend pool WASM set for the testnet network.
///
/// Contains the v2 hash; no v1 pool is deployed on the current Blend testnet.
#[must_use]
pub fn blend_pool_wasm_set_testnet() -> BlendPoolWasmSet {
    static HASHES: [[u8; 32]; 1] = [BLEND_V2_POOL_WASM_HASH_TESTNET];
    BlendPoolWasmSet {
        hashes: &HASHES,
        network: "testnet",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// verify_blend_pool_wasm
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies a Blend pool's on-chain WASM hash against the pinned set using a
/// two-RPC cross-check.
///
/// This is **step 1** of the ordered trust gate (pin-verify → oracle-allowlist →
/// oracle-read), which must complete before any oracle value is consumed.
///
/// The `secondary_rpc` is threaded at the gate call site, NOT via `DefiAdapterCtx`
/// which carries only a single `primary_rpc`.
///
/// # Errors
///
/// Returns [`BlendPinError`] when:
/// - The pool address is invalid.
/// - The on-chain WASM hash does not match any pinned hash (Drift).
/// - The pool is a SAC or absent (fail-closed by type).
/// - The primary or secondary RPC is unavailable.
/// - Primary and secondary RPC disagree (Divergent).
///
/// Performs a two-RPC WASM-hash set pin via
/// `stellar_agent_network::fetch_contract_wasm_hash`.
pub async fn verify_blend_pool_wasm(
    pool_address: &str,
    wasm_set: &BlendPoolWasmSet,
    primary_rpc: &StellarRpcClient,
    secondary_rpc: Option<&StellarRpcClient>,
) -> Result<(), BlendPinError> {
    // Fetch the on-chain WASM hash (two-RPC cross-check).
    let fetch = fetch_contract_wasm_hash(primary_rpc, secondary_rpc, pool_address)
        .await
        .map_err(|e| BlendPinError::FetchFailed {
            reason: format!("{e}"),
        })?;

    match fetch {
        WasmHashFetch::Wasm(on_chain_hash) => {
            // Match against any hash in the set (v1 OR v2).
            if wasm_set.hashes.contains(&on_chain_hash) {
                Ok(())
            } else {
                let first8: String = on_chain_hash[..8]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                Err(BlendPinError::HashMismatch {
                    pool_redacted: redact_strkey_first5_last5(pool_address),
                    on_chain_first8: first8,
                    network: wasm_set.network,
                })
            }
        }
        WasmHashFetch::Sac => Err(BlendPinError::SacNotPool {
            pool_redacted: redact_strkey_first5_last5(pool_address),
        }),
        WasmHashFetch::Absent => Err(BlendPinError::Absent {
            pool_redacted: redact_strkey_first5_last5(pool_address),
        }),
        // WasmHashFetch is #[non_exhaustive]; any future variants are also refused.
        _ => Err(BlendPinError::FetchFailed {
            reason: "unexpected WasmHashFetch variant (future extension)".to_owned(),
        }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BlendPinError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned by [`verify_blend_pool_wasm`].
///
/// All `Display` outputs carry only first-5-last-5 redacted addresses and
/// first-8-hex hashes; full hashes and addresses NEVER appear.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BlendPinError {
    /// The on-chain WASM hash does not match any pinned Blend pool hash.
    #[error(
        "Blend pool WASM hash mismatch for {pool_redacted} on {network}: on-chain={on_chain_first8}"
    )]
    HashMismatch {
        /// First-5-last-5 redacted pool address.
        pool_redacted: String,
        /// First-8 hex of the on-chain hash.
        on_chain_first8: String,
        /// Network label.
        network: &'static str,
    },

    /// The contract is a Stellar Asset Contract, not a Blend pool.
    #[error("address {pool_redacted} is a SAC, not a Blend pool")]
    SacNotPool {
        /// First-5-last-5 redacted address.
        pool_redacted: String,
    },

    /// The contract address is absent from the ledger.
    #[error("Blend pool {pool_redacted} is absent from the ledger")]
    Absent {
        /// First-5-last-5 redacted address.
        pool_redacted: String,
    },

    /// The WASM-hash fetch failed (RPC unavailable or divergent).
    #[error("Blend pool WASM-hash fetch failed: {reason}")]
    FetchFailed {
        /// Non-sensitive reason string (URL redacted to authority-only by the
        /// fetch primitive).
        reason: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Oracle allowlist check
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if `oracle_address` is in the Reflector allowlist for
/// `network`.
///
/// This is **step 2** of the ordered trust gate: called AFTER pin-verify passes,
/// BEFORE any oracle value (`lastprice`, `decimals`) is read.
///
/// Enforces the Reflector-only oracle allowlist.
#[must_use]
pub fn is_oracle_in_allowlist(oracle_address: &str, network: &str) -> bool {
    let list: &[&str] = match network {
        "pubnet" | "stellar:pubnet" | "Public Global Stellar Network ; September 2015" => {
            REFLECTOR_ORACLE_ALLOWLIST_PUBNET
        }
        "testnet" | "stellar:testnet" | "Test SDF Network ; September 2015" => {
            REFLECTOR_ORACLE_ALLOWLIST_TESTNET
        }
        // Unknown network label: fail closed (empty allowlist → refuse) rather
        // than inheriting the testnet allowlist.
        _ => &[],
    };
    list.contains(&oracle_address)
}

// ─────────────────────────────────────────────────────────────────────────────
// Const hex decoder
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
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

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
    fn v1_pubnet_hash_is_correct() {
        let hex = "baf978f10efdbcd85747868bef8832845ea6809f7643b67a4ac0cd669327fc2c";
        let expected: [u8; 32] = {
            let mut arr = [0u8; 32];
            for (i, b) in arr.iter_mut().enumerate() {
                let hi = u8::from_str_radix(&hex[i * 2..i * 2 + 1], 16).unwrap();
                let lo = u8::from_str_radix(&hex[i * 2 + 1..i * 2 + 2], 16).unwrap();
                *b = (hi << 4) | lo;
            }
            arr
        };
        assert_eq!(BLEND_V1_POOL_WASM_HASH_PUBNET, expected);
    }

    #[test]
    fn v2_hashes_are_identical_pubnet_and_testnet() {
        // The v2 pool uses the same WASM on pubnet and testnet.
        assert_eq!(
            BLEND_V2_POOL_WASM_HASH_PUBNET, BLEND_V2_POOL_WASM_HASH_TESTNET,
            "v2 WASM hash must be the same on both networks"
        );
    }

    // ── pool WASM set membership ──────────────────────────────────────────────

    #[test]
    fn pubnet_set_contains_v1_and_v2() {
        let set = blend_pool_wasm_set_pubnet();
        assert!(set.hashes.contains(&BLEND_V1_POOL_WASM_HASH_PUBNET));
        assert!(set.hashes.contains(&BLEND_V2_POOL_WASM_HASH_PUBNET));
    }

    #[test]
    fn testnet_set_contains_v2() {
        let set = blend_pool_wasm_set_testnet();
        assert!(set.hashes.contains(&BLEND_V2_POOL_WASM_HASH_TESTNET));
    }

    // ── oracle allowlist ──────────────────────────────────────────────────────

    #[test]
    fn reflector_oracle_is_in_pubnet_allowlist() {
        let oracle = "CCVTVW2CVA7JLH4ROQGP3CU4T3EXVCK66AZGSM4MUQPXAI4QHCZPOATS";
        assert!(is_oracle_in_allowlist(oracle, "pubnet"));
        assert!(is_oracle_in_allowlist(oracle, "stellar:pubnet"));
    }

    #[test]
    fn testnet_oracle_mock_is_in_testnet_allowlist() {
        let oracle = "CAZOKR2Y5E2OSWSIBRVZMJ47RUTQPIGVWSAQ2UISGAVC46XKPGDG5PKI";
        assert!(is_oracle_in_allowlist(oracle, "testnet"));
        assert!(is_oracle_in_allowlist(oracle, "stellar:testnet"));
    }

    #[test]
    fn rogue_oracle_is_not_in_allowlist() {
        let oracle = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        assert!(!is_oracle_in_allowlist(oracle, "pubnet"));
        assert!(!is_oracle_in_allowlist(oracle, "testnet"));
    }

    #[test]
    fn unknown_network_label_refuses_fail_closed() {
        // An unrecognized network label must NOT inherit the testnet allowlist;
        // a testnet-allowlisted oracle is refused on an unknown network.
        let testnet_oracle = "CAZOKR2Y5E2OSWSIBRVZMJ47RUTQPIGVWSAQ2UISGAVC46XKPGDG5PKI";
        assert!(
            is_oracle_in_allowlist(testnet_oracle, "testnet"),
            "sanity: the oracle is allowlisted on testnet"
        );
        assert!(
            !is_oracle_in_allowlist(testnet_oracle, "futurenet"),
            "unknown network must refuse even a testnet-allowlisted oracle"
        );
    }

    // ── BlendPinError Display does not leak full hash ─────────────────────────

    #[test]
    fn hash_mismatch_display_redacts_full_hash() {
        let err = BlendPinError::HashMismatch {
            pool_redacted: "CAAAA\u{2026}AAAAB".to_owned(),
            on_chain_first8: "baf978f1".to_owned(),
            network: "pubnet",
        };
        let display = err.to_string();
        let full_hash = "baf978f10efdbcd85747868bef8832845ea6809f7643b67a4ac0cd669327fc2c";
        assert!(
            !display.contains(full_hash),
            "full hash must not appear in Display"
        );
        assert!(display.contains("baf978f1"), "first-8 must appear");
    }

    #[test]
    fn sac_not_pool_display_labels_and_carries_redacted_address() {
        let err = BlendPinError::SacNotPool {
            pool_redacted: "CAAAA\u{2026}AAAAB".to_owned(),
        };
        let display = err.to_string();
        assert!(
            display.contains("SAC"),
            "must label the SAC refusal; got: {display}"
        );
        assert!(
            display.contains("CAAAA\u{2026}AAAAB"),
            "must carry the redacted pool address; got: {display}"
        );
        assert!(
            !display.contains("CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"),
            "no full C-strkey may leak into Display"
        );
    }

    #[test]
    fn absent_display_labels_and_carries_redacted_address() {
        let err = BlendPinError::Absent {
            pool_redacted: "CAAAA\u{2026}AAAAB".to_owned(),
        };
        let display = err.to_string();
        assert!(
            display.contains("absent"),
            "must label the absent refusal; got: {display}"
        );
        assert!(
            display.contains("CAAAA\u{2026}AAAAB"),
            "must carry the redacted pool address; got: {display}"
        );
    }

    #[test]
    fn fetch_failed_display_surfaces_reason() {
        let err = BlendPinError::FetchFailed {
            reason: "primary and secondary RPC diverged".to_owned(),
        };
        let display = err.to_string();
        assert!(
            display.contains("primary and secondary RPC diverged"),
            "must surface the non-sensitive reason; got: {display}"
        );
    }
}
