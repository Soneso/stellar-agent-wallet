//! Typed install-parameter builder and parser for the OZ simple-threshold
//! policy.
//!
//! The vendored WASM and wasm-hash allowlist for this policy already live at
//! [`crate::signers::policy_identification`] (`THRESHOLD_POLICY_WASM`,
//! `THRESHOLD_POLICY_WASM_HASHES`) — that module is the identification and
//! deploy-time-artefact home. This module holds only the typed install-param
//! builder and its inverse, kept separate so `smart-account rules add-policy
//! --kind simple-threshold` does not need to depend on the identification
//! module's allowlist machinery. The parser reads the threshold an install
//! or an attach of the policy sets, which the signer-set state row records.
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

/// Reads the threshold from an OZ `SimpleThresholdAccountParams`
/// install-parameter ScVal, the inverse of
/// [`build_simple_threshold_install_param`].
///
/// Accepts exactly the one-entry map `{ Symbol("threshold"): U32(t) }` with
/// `t >= 1`, the only parameter the policy's `install` accepts with a
/// threshold the wallet can record.
///
/// # Errors
///
/// Returns [`SaError::SimpleThresholdInstallRefused`] for any other shape: a
/// value that is not a map, a map with no entry or more than one entry, an
/// entry keyed by anything other than `Symbol("threshold")`, a value that is
/// not a `U32`, or a threshold of zero. The reason names the shape and never
/// echoes the value's bytes.
pub fn parse_simple_threshold_install_param(param: &ScVal) -> Result<u32, SaError> {
    let refuse = |reason: String| SaError::SimpleThresholdInstallRefused { reason };

    let entries: &[ScMapEntry] = match param {
        ScVal::Map(Some(ScMap(entries))) => entries.as_slice(),
        ScVal::Map(None) => &[],
        other => {
            return Err(refuse(format!(
                "install parameter is not a map (got {})",
                stellar_agent_core::scval::scval_variant_name(other)
            )));
        }
    };
    let [entry] = entries else {
        return Err(refuse(format!(
            "install parameter map has {} entries, expected exactly one (threshold)",
            entries.len()
        )));
    };
    match &entry.key {
        ScVal::Symbol(key) if key.as_slice() == b"threshold" => {}
        _ => {
            return Err(refuse(
                "install parameter map entry is not keyed by Symbol(\"threshold\")".to_owned(),
            ));
        }
    }
    match entry.val {
        ScVal::U32(0) => Err(refuse(
            "install parameter threshold is zero (OZ install rejects threshold == 0 with \
             InvalidThreshold)"
                .to_owned(),
        )),
        ScVal::U32(threshold) => Ok(threshold),
        ref other => Err(refuse(format!(
            "install parameter threshold is not a u32 (got {})",
            stellar_agent_core::scval::scval_variant_name(other)
        ))),
    }
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

    /// The parser reads back every threshold the builder writes.
    #[test]
    fn parse_round_trips_the_builder() {
        for threshold in [1_u32, 2, 15, u32::MAX] {
            let scval = build_simple_threshold_install_param(threshold).unwrap();
            assert_eq!(
                parse_simple_threshold_install_param(&scval).unwrap(),
                threshold
            );
        }
    }

    fn symbol(name: &str) -> ScVal {
        ScVal::Symbol(ScSymbol::try_from(name).unwrap())
    }

    fn map(entries: Vec<(ScVal, ScVal)>) -> ScVal {
        let entries: VecM<ScMapEntry> = entries
            .into_iter()
            .map(|(key, val)| ScMapEntry { key, val })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        ScVal::Map(Some(ScMap(entries)))
    }

    fn refusal_reason(param: &ScVal) -> String {
        match parse_simple_threshold_install_param(param) {
            Err(SaError::SimpleThresholdInstallRefused { reason }) => reason,
            other => panic!("expected SimpleThresholdInstallRefused, got {other:?}"),
        }
    }

    /// Every parameter other than the one-entry threshold map with a non-zero
    /// `U32` refuses, and the reason names the shape.
    #[test]
    fn parse_refuses_every_other_shape() {
        assert!(refusal_reason(&ScVal::Void).contains("not a map (got Void)"));
        assert!(refusal_reason(&ScVal::U32(2)).contains("not a map (got U32)"));
        assert!(refusal_reason(&ScVal::Map(None)).contains("has 0 entries"));
        assert!(refusal_reason(&map(vec![])).contains("has 0 entries"));
        assert!(
            refusal_reason(&map(vec![(symbol("limit"), ScVal::U32(2))]))
                .contains("not keyed by Symbol(\"threshold\")")
        );
        assert!(
            refusal_reason(&map(vec![(
                ScVal::String(stellar_xdr::ScString("threshold".try_into().unwrap())),
                ScVal::U32(2)
            )]))
            .contains("not keyed by Symbol(\"threshold\")")
        );
        assert!(
            refusal_reason(&map(vec![
                (symbol("threshold"), ScVal::U32(2)),
                (symbol("weights"), ScVal::U32(1)),
            ]))
            .contains("has 2 entries")
        );
        assert!(
            refusal_reason(&map(vec![(symbol("threshold"), ScVal::U64(2))]))
                .contains("not a u32 (got U64)")
        );
        assert!(
            refusal_reason(&map(vec![(symbol("threshold"), ScVal::U32(0))]))
                .contains("threshold is zero")
        );
    }
}
