//! Contract-pin framework for DeFi adapters.
//!
//! # What this module does
//!
//! Maintains per-profile, per-network, versioned `DefiContractPin` records and
//! provides two verification surfaces:
//!
//! - **Sign-time gate** (`verify_pin_for_sign`) — the only `Ok(())` path is a
//!   confirmed on-chain WASM hash that matches the pin.  Every other outcome
//!   (`Sac`, `Absent`, Drift, Unavailable, Divergent) maps to `Err` directly.
//!   "Proceed on Unavailable/absent/SAC" is unrepresentable by type.
//!
//! - **Report-only surface** (`check_pin_outcome`) — returns a `PinOutcome` for
//!   operator-facing inspection.  NOT consumed by any sign-time gate.
//!
//! # Key invariants
//!
//! - `wasm_hash: [u8; 32]` holds the FULL 32-byte deployed WASM hash; this is
//!   public deployment identity, not a secret.  Log and error surfaces redact to
//!   first-8 hex per the redaction rules (strkeys to first-5-last-5, WASM hashes
//!   to first-8 hex).
//! - `contract_address` is a `C…` strkey.  Log surfaces redact to
//!   first-5-last-5 per the redaction rules.
//! - The `Unavailable` error variant carries a typed wire-code (a `&'static str`
//!   constant), never a stringified RPC error.
//! - Full WASM hashes and contract addresses NEVER appear in `Display`, `Debug`,
//!   log events, or panic messages on this module's public types.

use stellar_agent_core::observability::redact_strkey_first5_last5;
use thiserror::Error;
use tracing::{debug, warn};

use crate::network::WasmHashFetch;

// ─────────────────────────────────────────────────────────────────────────────
// DefiContractPin
// ─────────────────────────────────────────────────────────────────────────────

/// A per-profile, per-network, versioned pin identifying a deployed DeFi
/// contract by its address and on-chain WASM hash.
///
/// The `wasm_hash` field is the FULL 32-byte deployment identity.  It is public
/// (not a secret) but log and error surfaces redact it to first-8 hex per
/// the redaction rules (strkeys to first-5-last-5, WASM hashes to first-8 hex).
/// `contract_address` is a `C…` strkey redacted to first-5-last-5 at info level.
///
/// # Debug output
///
/// The derived `Debug` would expose the full contract address and 32-byte WASM
/// hash in log events.  A manual `Debug` impl renders only the redacted forms
/// (first-5-last-5 address, first-8 hash hex) so `tracing::debug!(?pin)` cannot
/// leak the full values.
///
/// # Examples
///
/// ```
/// use stellar_agent_defi::pins::DefiContractPin;
///
/// let pin = DefiContractPin::new(
///     "blend", "v2", "default", "stellar:testnet",
///     "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
///     [0u8; 32], "895845f",
/// );
/// assert_eq!(pin.protocol, "blend");
/// ```
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct DefiContractPin {
    /// Protocol identifier (e.g. `"blend"`, `"defindex"`, `"axelar"`).
    pub protocol: String,
    /// Protocol version (e.g. `"v1"`, `"v2"`).
    pub version: String,
    /// Profile name under which this pin is active.
    pub profile: String,
    /// CAIP-2 network identifier (e.g. `stellar:testnet`, `stellar:pubnet`).
    pub network: String,
    /// Deployed contract address as a `C…` strkey.
    ///
    /// Log surfaces redact to first-5-last-5.  The full value is kept here
    /// for the fetch-and-compare gate.
    pub contract_address: String,
    /// Full 32-byte on-chain WASM hash.
    ///
    /// Log and error surfaces redact to first-8 hex.  Full hash is kept for
    /// the compare step in `verify_pin_for_sign`.
    pub wasm_hash: [u8; 32],
    /// ABI source-provenance: the git commit SHA (or other identifier) of the
    /// clone from which the ABI was bound (distinct from the deployed WASM hash).
    ///
    /// Example: `"895845f"` for Blend `blend-contracts@895845f`.
    pub abi_source_provenance: String,
}

impl DefiContractPin {
    /// Constructs a `DefiContractPin` with all required fields.
    ///
    /// Provided because `DefiContractPin` is `#[non_exhaustive]`; external
    /// callers cannot use struct-literal syntax and must use this constructor.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_defi::pins::DefiContractPin;
    ///
    /// let pin = DefiContractPin::new(
    ///     "blend", "v2", "default", "stellar:testnet",
    ///     "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
    ///     [0u8; 32], "895845f",
    /// );
    /// assert_eq!(pin.protocol, "blend");
    /// ```
    #[must_use]
    pub fn new(
        protocol: impl Into<String>,
        version: impl Into<String>,
        profile: impl Into<String>,
        network: impl Into<String>,
        contract_address: impl Into<String>,
        wasm_hash: [u8; 32],
        abi_source_provenance: impl Into<String>,
    ) -> Self {
        Self {
            protocol: protocol.into(),
            version: version.into(),
            profile: profile.into(),
            network: network.into(),
            contract_address: contract_address.into(),
            wasm_hash,
            abi_source_provenance: abi_source_provenance.into(),
        }
    }

    /// Returns a redacted representation of `contract_address` for use in
    /// log events: first 5 and last 5 characters separated by `"..."`.
    ///
    /// Implements first-5-last-5 redaction for `C…` strkeys at info level.
    #[must_use]
    pub fn redacted_address(&self) -> String {
        redact_strkey_first5_last5(&self.contract_address)
    }

    /// Returns the first 8 bytes of `wasm_hash` as a lowercase hex string.
    ///
    /// Implements WASM hash redaction for log/error surfaces.
    #[must_use]
    pub fn pin_hash_first8_hex(&self) -> String {
        hash_first8_hex(&self.wasm_hash)
    }
}

impl std::fmt::Debug for DefiContractPin {
    /// Renders redacted forms of sensitive fields.
    ///
    /// - `contract_address` → first-5-last-5 (e.g. `"CAAAA...AD2KM"`)
    /// - `wasm_hash` → first-8 bytes as lowercase hex (e.g. `"deadbeef..."`)
    ///
    /// Non-sensitive fields (`protocol`, `version`, `profile`, `network`,
    /// `abi_source_provenance`) render verbatim.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefiContractPin")
            .field("protocol", &self.protocol)
            .field("version", &self.version)
            .field("profile", &self.profile)
            .field("network", &self.network)
            .field(
                "contract_address",
                &redact_strkey_first5_last5(&self.contract_address),
            )
            .field("wasm_hash_first8", &hash_first8_hex(&self.wasm_hash))
            .field("abi_source_provenance", &self.abi_source_provenance)
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PinVerifyError — sign-time gate error (fail-closed by type)
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned by `verify_pin_for_sign`.
///
/// Every variant maps to a refused sign; `Ok(())` is the only proceed-to-sign
/// path.  The "proceed on Unavailable/absent/SAC" branch is unrepresentable.
///
/// All variants carry first-8 hex hashes and first-5-last-5 contract addresses
/// where applicable; NEVER the full 32-byte hash or full address.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PinVerifyError {
    /// The on-chain WASM hash does not match the pin.
    ///
    /// Fields carry first-8 hex redactions; full hashes never appear in
    /// `Display` or `Debug`.
    #[error(
        "DeFi contract pin DRIFT for {contract_redacted}: \
         pinned={pinned_first8} on-chain={observed_first8}"
    )]
    Drift {
        /// First-5-last-5 redacted contract address.
        contract_redacted: String,
        /// First-8 hex of the pinned `wasm_hash`.
        pinned_first8: String,
        /// First-8 hex of the on-chain WASM hash.
        observed_first8: String,
    },

    /// The contract is a Stellar Asset Contract (SAC); DeFi adapters only accept
    /// ordinary WASM contracts.
    ///
    /// The `contract_redacted` field carries first-5-last-5 of the address.
    /// `wire_code` is [`WIRE_CODE_SAC`] for machine-stable MCP-envelope mapping.
    #[error(
        "DeFi contract pin refused: {contract_redacted} is a Stellar Asset Contract (SAC), not a WASM contract (wire_code={wire_code})"
    )]
    IsSac {
        /// First-5-last-5 redacted contract address.
        contract_redacted: String,
        /// Typed machine-stable wire-code; always [`WIRE_CODE_SAC`].
        wire_code: &'static str,
    },

    /// The contract was not found on-chain (absent ledger entry).
    ///
    /// Refusing is fail-closed: the wallet cannot verify the contract identity.
    /// `wire_code` is [`WIRE_CODE_ABSENT`] for machine-stable MCP-envelope mapping.
    #[error(
        "DeFi contract pin refused: {contract_redacted} is absent from the ledger (wire_code={wire_code})"
    )]
    Absent {
        /// First-5-last-5 redacted contract address.
        contract_redacted: String,
        /// Typed machine-stable wire-code; always [`WIRE_CODE_ABSENT`].
        wire_code: &'static str,
    },

    /// The WASM-hash fetch failed or returned an error from the RPC layer.
    ///
    /// `wire_code` is a typed constant (`&'static str`), never a stringified RPC
    /// error, per the redaction rules.
    #[error(
        "DeFi contract pin unavailable for {contract_redacted}: \
         fetch failed (wire_code={wire_code})"
    )]
    Unavailable {
        /// First-5-last-5 redacted contract address.
        contract_redacted: String,
        /// Typed wire-code identifying the failure class (e.g. `"rpc.timeout"`).
        wire_code: &'static str,
    },

    /// Primary and secondary RPC disagree on the on-chain WASM hash.
    ///
    /// Fields carry first-8 hex redactions; full hashes never appear in
    /// `Display` or `Debug`.
    /// `wire_code` is [`WIRE_CODE_DIVERGENT`] for machine-stable MCP-envelope
    /// mapping.
    ///
    /// Reserved for when a concrete adapter wires a two-RPC cross-check by
    /// translating `stellar-agent-network`'s `WasmHashDivergenceError` into
    /// this variant.  No function in this crate currently constructs it.
    #[error(
        "DeFi contract pin DIVERGENT for {contract_redacted}: \
         primary={primary_first8} secondary={secondary_first8} (wire_code={wire_code})"
    )]
    Divergent {
        /// First-5-last-5 redacted contract address.
        contract_redacted: String,
        /// First-8 hex of the primary RPC's observed hash.
        primary_first8: String,
        /// First-8 hex of the secondary RPC's observed hash.
        secondary_first8: String,
        /// Typed machine-stable wire-code; always [`WIRE_CODE_DIVERGENT`].
        wire_code: &'static str,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// PinOutcome — report-only surface (NOT consumed by any gate)
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of a non-gating pin inspection call (`check_pin_outcome`).
///
/// This enum is **not consumed by any sign-time gate**; it is only for
/// operator-facing reporting (analogous to the `VerifyPinsResult` produced by
/// `stellar-agent-smart-account`'s rule-pin verifier for the `wallet rules
/// verify-pins` command).
///
/// All fields carry first-8 hex hashes and first-5-last-5 contract addresses;
/// full hashes and addresses are not exposed in `Display`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum PinOutcome {
    /// The on-chain WASM hash matches the pin.
    Match {
        /// First-5-last-5 redacted contract address.
        contract_redacted: String,
        /// First-8 hex of the matching hash.
        hash_first8: String,
    },
    /// The on-chain WASM hash differs from the pin.
    Drift {
        /// First-5-last-5 redacted contract address.
        contract_redacted: String,
        /// First-8 hex of the pinned hash.
        pinned_first8: String,
        /// First-8 hex of the on-chain hash.
        observed_first8: String,
    },
    /// The WASM-hash fetch was unavailable (RPC error, absent, or SAC).
    Unavailable {
        /// First-5-last-5 redacted contract address.
        contract_redacted: String,
        /// Typed wire-code.
        wire_code: &'static str,
    },
    /// Primary and secondary RPC disagreed.
    ///
    /// Reserved for when a concrete adapter wires a two-RPC cross-check.
    /// No code path in this crate currently constructs this variant.
    Divergent {
        /// First-5-last-5 redacted contract address.
        contract_redacted: String,
        /// First-8 hex from the primary RPC.
        primary_first8: String,
        /// First-8 hex from the secondary RPC.
        secondary_first8: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Sign-time gate
// ─────────────────────────────────────────────────────────────────────────────

/// Sign-time gate: verifies the on-chain WASM hash against the pin.
///
/// Returns `Ok(())` ONLY when `fetch` resolves to `WasmHashFetch::Wasm` whose
/// bytes match the pin's `wasm_hash` exactly.  Every other outcome
/// (`Sac`, `Absent`, Drift, Unavailable/fetch-error) returns `Err`.
///
/// This is **fail-closed by type**: `PinVerifyError` has no "proceed anyway"
/// variant; callers cannot reach submit without an `Ok(())`.
///
/// # Errors
///
/// - [`PinVerifyError::Drift`] — on-chain hash does not match the pin.
/// - [`PinVerifyError::IsSac`] — contract is a Stellar Asset Contract.
/// - [`PinVerifyError::Absent`] — contract not found on-chain.
/// - [`PinVerifyError::Unavailable`] — fetch failed (RPC error).
///
/// [`PinVerifyError::Divergent`] is reserved for a future two-RPC adapter
/// wiring; this function takes a single `&WasmHashFetch` and therefore never
/// constructs it.
///
/// # Design note
///
/// The `fetch` parameter accepts the `WasmHashFetch` tri-state returned by
/// `stellar_agent_network::fetch_contract_wasm_hash`.  `Absent` and `Sac`
/// map directly to `Err`, unlike `stellar-agent-smart-account`'s rule-pin
/// verifier path which uses an `unwrap_or([0u8; 32])` zero-sentinel (a
/// distinct accept-unknown-verifier install use-case with no DeFi analogue).
pub fn verify_pin_for_sign(
    pin: &DefiContractPin,
    fetch: &WasmHashFetch,
) -> Result<(), PinVerifyError> {
    let contract_redacted = pin.redacted_address();
    let pinned_first8 = pin.pin_hash_first8_hex();

    match fetch {
        WasmHashFetch::Wasm(observed) => {
            let observed_first8 = hash_first8_hex(observed);
            // Full 32-byte compare: any partial-match gate (e.g. first-8 bytes only)
            // would be a security weakness — 8-byte collisions are trivially cheap.
            if *observed == pin.wasm_hash {
                debug!(
                    contract_redacted = %contract_redacted,
                    hash_first8 = %observed_first8,
                    "defi pin verify: hash match"
                );
                Ok(())
            } else {
                warn!(
                    contract_redacted = %contract_redacted,
                    pinned_first8 = %pinned_first8,
                    observed_first8 = %observed_first8,
                    "defi pin verify: DRIFT — refusing sign"
                );
                Err(PinVerifyError::Drift {
                    contract_redacted,
                    pinned_first8,
                    observed_first8,
                })
            }
        }
        // SAC: DeFi adapters only accept WASM contracts. Fail-closed.
        //
        // ContractExecutable::StellarAsset is the on-chain variant for Stellar
        // Asset Contracts (SACs) — verified against stellar-xdr at the
        // `ContractExecutable` enum (`StellarAsset` variant). The mapping
        // `Sac → Err` is stricter than stellar-agent-smart-account's rule-pin
        // verifier, which uses `unwrap_or([0u8;32])` for its
        // accept-unknown-verifier install use case — a distinct path with no
        // DeFi analogue.
        WasmHashFetch::Sac => {
            warn!(
                contract_redacted = %contract_redacted,
                "defi pin verify: SAC — refusing sign (only WASM contracts accepted)"
            );
            Err(PinVerifyError::IsSac {
                contract_redacted,
                wire_code: WIRE_CODE_SAC,
            })
        }
        // Absent: the contract is not deployed. Fail-closed.
        WasmHashFetch::Absent => {
            warn!(
                contract_redacted = %contract_redacted,
                "defi pin verify: ABSENT — refusing sign"
            );
            Err(PinVerifyError::Absent {
                contract_redacted,
                wire_code: WIRE_CODE_ABSENT,
            })
        }
        // WasmHashFetch is #[non_exhaustive]; fail-closed on any unknown variant.
        // This arm is intentionally unreachable with the current upstream variants
        // but required by the #[non_exhaustive] attribute.
        //
        // NOTE: Any future `WasmHashFetch` variant added upstream MUST be
        // deliberately triaged here before merging.  Routing unknown variants
        // to `PinVerifyError::Unavailable` (fail-closed) is the intentional
        // default — the sign-time gate must never silently proceed on an
        // unrecognised on-chain state.
        _ => {
            warn!(
                contract_redacted = %contract_redacted,
                "defi pin verify: unknown WasmHashFetch variant — refusing sign (fail-closed)"
            );
            Err(PinVerifyError::Unavailable {
                contract_redacted,
                wire_code: WIRE_CODE_FETCH_FAILED,
            })
        }
    }
}

/// Report-only pin check: returns a `PinOutcome` for operator inspection.
///
/// This function does NOT gate signing.  It is the report-only counterpart to
/// [`verify_pin_for_sign`], analogous to `stellar-agent-smart-account`'s
/// rule-pin verifier which produces a verification result for the
/// `wallet rules verify-pins` command.
///
/// The result is intentionally separate from `verify_pin_for_sign` to make it
/// structurally impossible for a caller to accidentally route a report-only call
/// into the sign-time gate path.
///
/// This function is infallible — it maps every fetch outcome to a `PinOutcome`
/// variant without returning a `Result`.  Any error conditions (RPC failure,
/// Absent, Divergent) become `PinOutcome::Unavailable` or `PinOutcome::Divergent`.
pub fn check_pin_outcome(pin: &DefiContractPin, fetch: &WasmHashFetch) -> PinOutcome {
    let contract_redacted = pin.redacted_address();
    let pinned_first8 = pin.pin_hash_first8_hex();

    match fetch {
        WasmHashFetch::Wasm(observed) => {
            let observed_first8 = hash_first8_hex(observed);
            if *observed == pin.wasm_hash {
                PinOutcome::Match {
                    contract_redacted,
                    hash_first8: observed_first8,
                }
            } else {
                PinOutcome::Drift {
                    contract_redacted,
                    pinned_first8,
                    observed_first8,
                }
            }
        }
        WasmHashFetch::Sac => PinOutcome::Unavailable {
            contract_redacted,
            wire_code: WIRE_CODE_SAC,
        },
        WasmHashFetch::Absent => PinOutcome::Unavailable {
            contract_redacted,
            wire_code: WIRE_CODE_ABSENT,
        },
        // WasmHashFetch is #[non_exhaustive]; map unknown variants to Unavailable.
        //
        // NOTE: Any future `WasmHashFetch` variant added upstream MUST be
        // deliberately triaged here before merging.  Routing unknown variants
        // to `PinOutcome::Unavailable` (fail-closed) is the intentional
        // default — the report-only surface must not claim a match or drift on
        // an unrecognised on-chain state.
        _ => PinOutcome::Unavailable {
            contract_redacted,
            wire_code: WIRE_CODE_FETCH_FAILED,
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire-code constants for Unavailable carriers
// ─────────────────────────────────────────────────────────────────────────────

/// Typed wire-code: contract is a Stellar Asset Contract.
pub const WIRE_CODE_SAC: &str = "defi.pin.sac";
/// Typed wire-code: contract not found on-chain.
pub const WIRE_CODE_ABSENT: &str = "defi.pin.absent";
/// Typed wire-code: RPC fetch failed.
pub const WIRE_CODE_FETCH_FAILED: &str = "defi.pin.fetch_failed";
/// Typed wire-code: primary and secondary RPC disagree.
///
/// Reserved for when a concrete adapter wires the two-RPC cross-check
/// (translating `stellar-agent-network`'s `WasmHashDivergenceError`).
/// Currently unconstructed.
pub const WIRE_CODE_DIVERGENT: &str = "defi.pin.divergent";

// ─────────────────────────────────────────────────────────────────────────────
// Internal redaction helpers
// ─────────────────────────────────────────────────────────────────────────────

// `redact_strkey_first5_last5` is imported from
// `stellar_agent_core::observability::redact_strkey_first5_last5` at the top
// of this file.  That function is the canonical implementation shared across
// all workspace crates.

/// Returns the first 8 bytes of a 32-byte hash as lowercase hex (16 chars).
///
/// Used for log and error surfaces per the WASM-hash redaction rule (first-8 hex).
///
/// This is intentionally local to this crate.
/// `stellar_agent_core::hex::redact_hex_first8_last8` operates on hex strings
/// (not raw bytes) and returns first-8-last-8.  The sign-time gate requires
/// first-8-only from raw `[u8; 32]` bytes, which has no matching core
/// primitive.
#[must_use]
pub(crate) fn hash_first8_hex(hash: &[u8; 32]) -> String {
    hash[..8].iter().map(|b| format!("{b:02x}")).collect()
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
    use crate::network::WasmHashFetch;

    fn test_pin(wasm_hash: [u8; 32]) -> DefiContractPin {
        DefiContractPin {
            protocol: "blend".to_owned(),
            version: "v2".to_owned(),
            profile: "default".to_owned(),
            network: "stellar:testnet".to_owned(),
            contract_address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            wasm_hash,
            abi_source_provenance: "895845f".to_owned(),
        }
    }

    // ── Constructor ─────────────────────────────────────────────────────────

    #[test]
    fn defi_contract_pin_new_constructor() {
        let hash = [0xaau8; 32];
        let pin = DefiContractPin::new(
            "blend",
            "v2",
            "default",
            "stellar:testnet",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            hash,
            "895845f",
        );
        assert_eq!(pin.protocol, "blend");
        assert_eq!(pin.version, "v2");
        assert_eq!(pin.profile, "default");
        assert_eq!(pin.wasm_hash, hash);
        // Verify redacted helpers work on constructor-built pin.
        assert!(pin.redacted_address().contains("CAAAA"));
        assert_eq!(pin.pin_hash_first8_hex().len(), 16);
    }

    #[test]
    fn defi_contract_pin_debug_is_redacted() {
        let hash = [0xdeu8; 32];
        let pin = test_pin(hash);
        let debug = format!("{pin:?}");
        // Full 32-byte hex (64 chars) must not appear.
        let full_hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            !debug.contains(&full_hex),
            "full hash in Debug output: {debug}"
        );
        // Full contract address must not appear.
        assert!(
            !debug.contains("CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"),
            "full address in Debug output: {debug}"
        );
        // First-8 hex must appear (16 chars of 'de').
        assert!(
            debug.contains("dededede"),
            "first-8 hex not in Debug output: {debug}"
        );
    }

    // ── Match ────────────────────────────────────────────────────────────────

    #[test]
    fn verify_pin_for_sign_match_ok() {
        let hash = [1u8; 32];
        let pin = test_pin(hash);
        assert!(verify_pin_for_sign(&pin, &WasmHashFetch::Wasm(hash)).is_ok());
    }

    #[test]
    fn check_pin_outcome_match() {
        let hash = [1u8; 32];
        let pin = test_pin(hash);
        let outcome = check_pin_outcome(&pin, &WasmHashFetch::Wasm(hash));
        assert!(matches!(outcome, PinOutcome::Match { .. }));
    }

    // ── Drift ────────────────────────────────────────────────────────────────

    #[test]
    fn verify_pin_for_sign_drift_err() {
        let pinned = [1u8; 32];
        let observed = [2u8; 32];
        let pin = test_pin(pinned);
        let result = verify_pin_for_sign(&pin, &WasmHashFetch::Wasm(observed));
        assert!(matches!(result, Err(PinVerifyError::Drift { .. })));
    }

    #[test]
    fn check_pin_outcome_drift() {
        let pinned = [1u8; 32];
        let observed = [2u8; 32];
        let pin = test_pin(pinned);
        let outcome = check_pin_outcome(&pin, &WasmHashFetch::Wasm(observed));
        assert!(matches!(outcome, PinOutcome::Drift { .. }));
    }

    // ── Unavailable / SAC ────────────────────────────────────────────────────

    #[test]
    fn verify_pin_for_sign_sac_err() {
        let pin = test_pin([1u8; 32]);
        let result = verify_pin_for_sign(&pin, &WasmHashFetch::Sac);
        assert!(matches!(result, Err(PinVerifyError::IsSac { .. })));
    }

    #[test]
    fn check_pin_outcome_sac_is_unavailable_with_typed_wire_code() {
        let pin = test_pin([1u8; 32]);
        let outcome = check_pin_outcome(&pin, &WasmHashFetch::Sac);
        assert!(matches!(
            outcome,
            PinOutcome::Unavailable {
                wire_code: WIRE_CODE_SAC,
                ..
            }
        ));
    }

    // ── Absent ───────────────────────────────────────────────────────────────

    #[test]
    fn verify_pin_for_sign_absent_err() {
        let pin = test_pin([1u8; 32]);
        let result = verify_pin_for_sign(&pin, &WasmHashFetch::Absent);
        assert!(matches!(result, Err(PinVerifyError::Absent { .. })));
    }

    #[test]
    fn check_pin_outcome_absent_is_unavailable_with_typed_wire_code() {
        let pin = test_pin([1u8; 32]);
        let outcome = check_pin_outcome(&pin, &WasmHashFetch::Absent);
        assert!(matches!(
            outcome,
            PinOutcome::Unavailable {
                wire_code: WIRE_CODE_ABSENT,
                ..
            }
        ));
    }

    // ── Redaction helpers ────────────────────────────────────────────────────

    #[test]
    fn redact_strkey_first5_last5_format() {
        let strkey = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        let redacted = redact_strkey_first5_last5(strkey);
        // First 5 chars
        assert!(
            redacted.starts_with("CAAAA"),
            "must start with first-5: {redacted}"
        );
        // Last 5 chars of the 56-char strkey: "AD2KM"
        assert!(
            redacted.ends_with("AD2KM"),
            "must end with last-5: {redacted}"
        );
        // core's redact_strkey_first5_last5 uses "..." (three ASCII dots)
        assert!(redacted.contains("..."));
        // Full strkey must NOT appear
        assert!(!redacted.contains("CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"));
    }

    #[test]
    fn hash_first8_hex_is_16_chars() {
        let hash = [
            0xdeu8, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let hex = hash_first8_hex(&hash);
        assert_eq!(hex, "deadbeefcafebabe");
        assert_eq!(hex.len(), 16);
    }

    // ── Display/Debug redaction audit ────────────────────────────────────────
    //
    // These tests assert that the full 32-byte hash and full contract address
    // NEVER appear in Display/Debug output of the error types.

    #[test]
    fn pin_verify_error_drift_display_redacts_full_hash() {
        let pinned = [0xabu8; 32];
        let observed = [0xcdu8; 32];
        let pin = test_pin(pinned);
        let err = verify_pin_for_sign(&pin, &WasmHashFetch::Wasm(observed)).unwrap_err();
        let display = err.to_string();
        // Full 32-byte hex (64 chars of "ab" repeated) must not appear
        let full_pinned_hex: String = pinned.iter().map(|b| format!("{b:02x}")).collect();
        let full_observed_hex: String = observed.iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            !display.contains(&full_pinned_hex),
            "full pinned hash in Display: {display}"
        );
        assert!(
            !display.contains(&full_observed_hex),
            "full observed hash in Display: {display}"
        );
        // first-8 hex must appear
        assert!(
            display.contains("abababab"),
            "first-8 of pinned not in Display: {display}"
        );
        assert!(
            display.contains("cdcdcdcd"),
            "first-8 of observed not in Display: {display}"
        );
    }

    #[test]
    fn pin_verify_error_display_redacts_full_contract_address() {
        let pin = test_pin([1u8; 32]);
        let full_addr = pin.contract_address.clone();
        let err = verify_pin_for_sign(&pin, &WasmHashFetch::Sac).unwrap_err();
        let display = err.to_string();
        assert!(
            !display.contains(&full_addr),
            "full contract address in Display: {display}"
        );
    }
}
