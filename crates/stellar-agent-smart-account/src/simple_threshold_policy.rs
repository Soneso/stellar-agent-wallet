//! Typed install-parameter builder for the OZ simple-threshold policy.
//!
//! The vendored WASM and wasm-hash allowlist for this policy already live at
//! [`crate::signers::policy_identification`] (`THRESHOLD_POLICY_WASM`,
//! `THRESHOLD_POLICY_WASM_HASHES`) — that module is the identification and
//! deploy-time-artefact home. This module holds only the typed install-param
//! builder, kept separate so `smart-account rules add-policy --kind
//! simple-threshold` does not need to depend on the identification module's
//! allowlist machinery.
//!
//! # Byte layout
//!
//! `SimpleThresholdAccountParams { threshold: u32 }` is a soroban-sdk
//! `#[contracttype]` struct with a SINGLE field
//! (`packages/accounts/src/policies/simple_threshold.rs:96-101`, SHA
//! `a9c4216`). A `#[contracttype]` struct encodes to `ScVal::Map` with one
//! `ScMapEntry` per field, keyed by `ScVal::Symbol(field_name)` — this is a
//! ONE-ENTRY map `{ Symbol("threshold"): U32(threshold) }`, never a bare
//! `ScVal::U32`. This trap is documented at
//! `crate::managers::mod` module rustdoc.

use stellar_xdr::{ScMap, ScMapEntry, ScSymbol, ScVal, VecM};

use crate::SaError;

/// Builds the OZ `SimpleThresholdAccountParams` install-parameter ScVal for
/// `add_policy`.
///
/// Produces the one-entry map `{ Symbol("threshold"): U32(threshold) }` — see
/// module rustdoc for why this is a map and not a bare `ScVal::U32`.
///
/// # Errors
///
/// Returns [`SaError::SimpleThresholdInstallRefused`] when `threshold == 0`
/// (OZ `install` panics `InvalidThreshold`,
/// `simple_threshold.rs:151-159`, SHA `a9c4216`) or if the fixed Symbol /
/// one-entry map cannot be XDR-encoded — unreachable for this bounded input,
/// but surfaced rather than panicking.
pub fn build_simple_threshold_install_param(threshold: u32) -> Result<ScVal, SaError> {
    let refuse = |reason: String| SaError::SimpleThresholdInstallRefused { reason };

    if threshold == 0 {
        return Err(refuse(
            "--threshold must be non-zero (OZ install rejects threshold == 0 with \
             InvalidThreshold)"
                .to_owned(),
        ));
    }

    let threshold_sym = ScSymbol::try_from("threshold")
        .map_err(|e| refuse(format!("encode threshold symbol: {e:?}")))?;

    let entries: VecM<ScMapEntry> = vec![ScMapEntry {
        key: ScVal::Symbol(threshold_sym),
        val: ScVal::U32(threshold),
    }]
    .try_into()
    .map_err(|e| refuse(format!("encode SimpleThresholdAccountParams ScMap: {e:?}")))?;

    Ok(ScVal::Map(Some(ScMap(entries))))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    #![allow(clippy::expect_used, reason = "test-only")]
    #![allow(clippy::panic, reason = "test-only shape assertions")]

    use super::*;

    /// The install-param ScMap is a ONE-ENTRY map keyed by `Symbol("threshold")`
    /// — never a bare `ScVal::U32`.
    #[test]
    fn install_param_is_one_entry_map_not_bare_u32() {
        let scval = build_simple_threshold_install_param(3).expect("build install param");

        let ScVal::Map(Some(ScMap(entries))) = &scval else {
            panic!("install param must be ScVal::Map, not a bare ScVal::U32");
        };
        assert_eq!(entries.len(), 1, "exactly one struct field");

        let ScVal::Symbol(key) = &entries[0].key else {
            panic!("key must be Symbol")
        };
        assert_eq!(key.to_utf8_string_lossy(), "threshold");
        assert_eq!(entries[0].val, ScVal::U32(3));
    }

    /// `threshold == 0` is refused before any XDR encoding.
    #[test]
    fn zero_threshold_is_refused() {
        let err = build_simple_threshold_install_param(0).expect_err("threshold 0 must refuse");
        assert!(matches!(err, SaError::SimpleThresholdInstallRefused { .. }));
    }

    /// A range of valid non-zero thresholds all build successfully.
    #[test]
    fn nonzero_thresholds_build_successfully() {
        for threshold in [1_u32, 2, 15, u32::MAX] {
            let scval = build_simple_threshold_install_param(threshold)
                .unwrap_or_else(|_| panic!("threshold {threshold} must build"));
            let ScVal::Map(Some(ScMap(entries))) = &scval else {
                panic!("map")
            };
            assert_eq!(entries[0].val, ScVal::U32(threshold));
        }
    }
}
