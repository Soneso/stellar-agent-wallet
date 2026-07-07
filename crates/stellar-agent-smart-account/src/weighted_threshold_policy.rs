//! OZ `multisig-weighted-threshold-policy-example` v0.7.2 vendored WASM.
//!
//! Built from OZ `stellar-contracts` at SHA `a9c4216` (tag `v0.7.2`) via
//! `stellar contract build --package multisig-weighted-threshold-policy-example`
//! (stellar-cli 25.2.0). The resulting cdylib is the `release` profile output
//! (`target/wasm32v1-none/release/multisig_weighted_threshold_policy_example.wasm`)
//! — the deployable production contract, not a `contractimport!` artefact.
//!
//! # What this WASM does
//!
//! Soroban contract implementing the OZ `Policy` trait plus a query/mutator
//! surface (per OZ
//! `examples/multisig-smart-account/weighted-threshold-policy/src/contract.rs`
//! at SHA `a9c4216`), delegating to
//! `stellar_accounts::policies::weighted_threshold`. It enforces a
//! weighted-signer quorum:
//!
//! - `enforce(...)` sums the stored weight of every authenticated signer and
//!   panics `NotAllowed` (3213) if the total is below the stored `threshold`
//!   (`weighted_threshold.rs:293-323`, SHA `a9c4216`).
//! - `install(...)` places **no restriction** on `context_rule.context_type`
//!   — unlike the spending-limit policy, ANY context type is accepted
//!   (`weighted_threshold.rs:482-512`, SHA `a9c4216`). Panics
//!   `InvalidThreshold` (3211) when `threshold == 0` or `threshold` exceeds
//!   the checked sum of `signer_weights` values, and `MathOverflow` (3212) on
//!   weight-sum overflow.
//! - `uninstall`, `get_threshold`, `get_signer_weights`, `set_threshold`,
//!   `set_signer_weight` — as per the `weighted_threshold` module.
//!
//! `WeightedThresholdAccountParams` is a `#[contracttype]` struct whose ScMap
//! encoding sorts keys alphabetically by field name, so the install param
//! ScMap has `signer_weights` before `threshold` ('s' 0x73 < 't' 0x74).
//!
//! # Per-network singleton
//!
//! The policy keys all state by
//! `WeightedThresholdStorageKey::AccountContext(smart_account, context_rule_id)`
//! (`weighted_threshold.rs:158`), so one deployed instance serves every account
//! and every context rule on the network. The wallet deploys exactly one per
//! network via `smart-account deploy-policy --kind weighted-threshold` and
//! records the address in the wallet-local registry
//! (`~/.config/stellar-agent/networks.toml`).
//!
//! # Supply-chain integrity
//!
//! The SHA-256 of the vendored WASM is verified in the unit test
//! `tests::weighted_threshold_policy_wasm_sha256_matches_provenance` below, on
//! every `cargo test`. The SHA-256 value is pinned in three places (this
//! file, `build.rs`, and
//! `vendor/oz-weighted-threshold-policy/v0.7.2/PROVENANCE.md`), and the CI
//! vendored-wasm gate re-hashes the in-repo WASM against PROVENANCE.md on
//! every run.

/// SHA-256 of the vendored `multisig_weighted_threshold_policy_example.wasm`
/// artefact.
///
/// Pinned here, in `build.rs`, and in
/// `vendor/oz-weighted-threshold-policy/v0.7.2/PROVENANCE.md` (same value in
/// all places). The compile-time integrity gate is `build.rs`; the runtime
/// `tests::weighted_threshold_policy_wasm_sha256_matches_provenance` test
/// remains as defense in depth.
///
/// Built from OZ `stellar-contracts` at SHA `a9c42169000638da937577f592ebf61a7a3c94ca`
/// (tag `v0.7.2`) via `stellar contract build --package multisig-weighted-threshold-policy-example`
/// (stellar-cli 25.2.0), then copying the release cdylib from
/// `target/wasm32v1-none/release/multisig_weighted_threshold_policy_example.wasm`.
pub const WEIGHTED_THRESHOLD_POLICY_WASM_SHA256: &str =
    "e3d8cc5ab9668526d5cf2bab17ee42e84ee4b972ba7cca8d3a37b2ed8d9baee3";

/// The vendored `multisig_weighted_threshold_policy_example.wasm` binary,
/// embedded at compile time.
///
/// Embedded so the deploy CLI (`smart-account deploy-policy --kind
/// weighted-threshold`) can upload the WASM via `UploadContractWasm` without
/// re-fetching from disk at runtime; the bytes are passed by reference to the
/// deployment substrate.
pub const WEIGHTED_THRESHOLD_POLICY_WASM: &[u8] = include_bytes!(
    "../vendor/oz-weighted-threshold-policy/v0.7.2/multisig_weighted_threshold_policy_example.wasm"
);

/// SHA-256 allowlist for audited weighted-threshold-policy WASM deployments.
///
/// Single-entry allowlist (unlike [`crate::signers::policy_identification::THRESHOLD_POLICY_WASM_HASHES`]'s
/// two entries — this policy has no legacy version to grandfather). Separate
/// from the simple-threshold allowlist: `identify_threshold_policy` matches
/// ONLY simple-threshold hashes and `identify_weighted_threshold_policy`
/// matches ONLY this array, so the two policy kinds cannot cross-identify.
///
/// Each entry is a 32-byte raw SHA-256 digest — the same value pinned in
/// [`WEIGHTED_THRESHOLD_POLICY_WASM_SHA256`] (as a hex string) and in
/// `vendor/oz-weighted-threshold-policy/v0.7.2/PROVENANCE.md`.
pub const WEIGHTED_THRESHOLD_POLICY_WASM_HASHES: &[[u8; 32]] = &[[
    0xe3, 0xd8, 0xcc, 0x5a, 0xb9, 0x66, 0x85, 0x26, 0xd5, 0xcf, 0x2b, 0xab, 0x17, 0xee, 0x42, 0xe8,
    0x4e, 0xe4, 0xb9, 0x72, 0xba, 0x7c, 0xca, 0x8d, 0x3a, 0x37, 0xb2, 0xed, 0x8d, 0x9b, 0xae, 0xe3,
]];

use stellar_xdr::{ScAddress, ScMap, ScMapEntry, ScSymbol, ScVal, VecM};

use crate::SaError;
use crate::managers::signers::{build_delegated_signer_scval, build_external_signer_scval};

/// One signer's identity for a weighted-threshold `signer_weights` map entry.
///
/// Carries the RAW inputs the two canonical signer-key encoders
/// ([`build_delegated_signer_scval`], [`build_external_signer_scval`]) expect
/// — a G-strkey `&str` for `Delegated`, an `ScAddress` + raw key bytes for
/// `External` — rather than a pre-parsed `ScAddress`, so this module never
/// reimplements the `Signer` key-encoding shape.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum WeightedThresholdSignerInput {
    /// A delegated (built-in ed25519) signer, identified by G-strkey.
    Delegated {
        /// The signer's G-strkey (`GABC...`).
        g_strkey: String,
    },
    /// An external signer verified by a registered verifier contract.
    External {
        /// Verifier-contract address.
        verifier: ScAddress,
        /// Verifier-specific raw public-key bytes.
        key_data: Vec<u8>,
    },
}

/// Builds the OZ `WeightedThresholdAccountParams` install-parameter ScVal for
/// `add_policy`.
///
/// `WeightedThresholdAccountParams { signer_weights: Map<Signer, u32>,
/// threshold: u32 }` is a soroban-sdk `#[contracttype]` struct
/// (`packages/accounts/src/policies/weighted_threshold.rs:126-133`, SHA
/// `a9c4216`). The outer `#[contracttype]` struct ScMap is keyed by
/// `ScVal::Symbol(field_name)` in ascending byte-lexicographic order:
/// `"signer_weights"` precedes `"threshold"` (`'s'` 0x73 < `'t'` 0x74).
///
/// The inner `signer_weights` map keys are `Signer` ScVals built via
/// [`build_delegated_signer_scval`] / [`build_external_signer_scval`] — the
/// same canonical encoders the multi-signer auth-payload path uses — sorted
/// ascending by the canonical `ScVal` `Ord` (the soroban host's `Compare<ScVal>`
/// total order for `ScMap` validity), matching the ordering rule established
/// by `build_multi_signer_auth_payload_scval` (`managers/auth_entry.rs`): a
/// `Delegated` key differs from an `External` key at the tag `Symbol`
/// (`"Delegated"` < `"External"`), so all Delegated entries sort before all
/// External entries.
///
/// # Errors
///
/// Returns [`SaError::WeightedThresholdInstallRefused`] when:
/// - `signer_weights` is empty.
/// - Any weight is `0`.
/// - `threshold == 0`.
/// - The checked sum of weights overflows `u32`.
/// - `threshold` exceeds the checked sum of weights (OZ `install` panics
///   `InvalidThreshold`, `weighted_threshold.rs:499-501`, SHA `a9c4216`).
/// - Two signers encode to the same map key (would violate the on-chain
///   `ScMap` validity rule — ambiguous weight for one signer).
/// - Any signer G-strkey / verifier address / key data cannot be encoded.
pub fn build_weighted_threshold_install_param(
    signer_weights: &[(WeightedThresholdSignerInput, u32)],
    threshold: u32,
) -> Result<ScVal, SaError> {
    let refuse = |reason: String| SaError::WeightedThresholdInstallRefused { reason };

    if signer_weights.is_empty() {
        return Err(refuse(
            "signer_weights must not be empty (OZ install computes threshold against the \
             sum of signer weights)"
                .to_owned(),
        ));
    }
    if threshold == 0 {
        return Err(refuse(
            "--threshold must be non-zero (OZ install rejects threshold == 0 with \
             InvalidThreshold)"
                .to_owned(),
        ));
    }

    let mut total_weight: u32 = 0;
    for (_, weight) in signer_weights {
        if *weight == 0 {
            return Err(refuse(
                "every signer weight must be non-zero; a zero-weight signer contributes \
                 nothing and is rejected client-side to avoid a confusing install"
                    .to_owned(),
            ));
        }
        total_weight = total_weight.checked_add(*weight).ok_or_else(|| {
            refuse(
                "sum of signer weights overflows u32 (OZ install panics MathOverflow)".to_owned(),
            )
        })?;
    }

    if threshold > total_weight {
        return Err(refuse(format!(
            "--threshold ({threshold}) must not exceed the sum of signer weights \
             ({total_weight}); OZ install rejects this with InvalidThreshold"
        )));
    }

    // Build (key, value) pairs for the inner signer_weights map.
    let mut keyed: Vec<(ScVal, ScVal)> = Vec::with_capacity(signer_weights.len());
    for (signer, weight) in signer_weights {
        let key = match signer {
            WeightedThresholdSignerInput::Delegated { g_strkey } => {
                build_delegated_signer_scval(g_strkey)?
            }
            WeightedThresholdSignerInput::External { verifier, key_data } => {
                build_external_signer_scval(verifier.clone(), key_data)?
            }
        };
        keyed.push((key, ScVal::U32(*weight)));
    }

    // Canonical ScMap key order: ascending by the key ScVal (element-wise for
    // ScVal::Vec), matching the soroban host's Compare<ScVal> — the same rule
    // `build_multi_signer_auth_payload_scval` applies to the AuthPayload
    // signers map.
    keyed.sort_by(|(a, _), (b, _)| a.cmp(b));

    for pair in keyed.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(refuse(
                "duplicate signer in signer_weights (two entries encode to the same map key)"
                    .to_owned(),
            ));
        }
    }

    let inner_entries: VecM<ScMapEntry> = keyed
        .into_iter()
        .map(|(key, val)| ScMapEntry { key, val })
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|e| refuse(format!("encode signer_weights ScMap: {e:?}")))?;
    let signer_weights_map = ScVal::Map(Some(ScMap(inner_entries)));

    let signer_weights_sym = ScSymbol::try_from("signer_weights")
        .map_err(|e| refuse(format!("encode signer_weights symbol: {e:?}")))?;
    let threshold_sym = ScSymbol::try_from("threshold")
        .map_err(|e| refuse(format!("encode threshold symbol: {e:?}")))?;

    // signer_weights FIRST (alphabetical key order), threshold second.
    let outer_entries: VecM<ScMapEntry> = vec![
        ScMapEntry {
            key: ScVal::Symbol(signer_weights_sym),
            val: signer_weights_map,
        },
        ScMapEntry {
            key: ScVal::Symbol(threshold_sym),
            val: ScVal::U32(threshold),
        },
    ]
    .try_into()
    .map_err(|e| {
        refuse(format!(
            "encode WeightedThresholdAccountParams ScMap: {e:?}"
        ))
    })?;

    Ok(ScVal::Map(Some(ScMap(outer_entries))))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    #![allow(clippy::expect_used, reason = "test-only")]
    #![allow(clippy::panic, reason = "test-only shape assertions")]

    use sha2::{Digest as _, Sha256};
    use stellar_agent_core::constants::SIMULATE_SENTINEL_G;
    use stellar_xdr::{ContractId, Hash};

    use super::*;

    fn ed25519_g_strkey(byte_fill: u8) -> String {
        stellar_strkey::ed25519::PublicKey([byte_fill; 32])
            .to_string()
            .as_str()
            .to_owned()
    }

    fn verifier_sc_address(contract_id_fill: u8) -> ScAddress {
        ScAddress::Contract(ContractId(Hash([contract_id_fill; 32])))
    }

    /// Asserts that `SHA256(WEIGHTED_THRESHOLD_POLICY_WASM)` matches the
    /// pinned `WEIGHTED_THRESHOLD_POLICY_WASM_SHA256` const. Supply-chain
    /// integrity gate; fires on every `cargo test`.
    #[test]
    fn weighted_threshold_policy_wasm_sha256_matches_provenance() {
        let mut hasher = Sha256::new();
        hasher.update(WEIGHTED_THRESHOLD_POLICY_WASM);
        let digest: [u8; 32] = hasher.finalize().into();
        let actual: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            actual, WEIGHTED_THRESHOLD_POLICY_WASM_SHA256,
            "vendored multisig_weighted_threshold_policy_example.wasm sha256 mismatch: \
             expected {WEIGHTED_THRESHOLD_POLICY_WASM_SHA256}, got {actual}. \
             If the WASM was intentionally updated, regenerate via \
             vendor/oz-weighted-threshold-policy/v0.7.2/build.sh and update both \
             WEIGHTED_THRESHOLD_POLICY_WASM_SHA256 and PROVENANCE.md."
        );
    }

    /// `WEIGHTED_THRESHOLD_POLICY_WASM_HASHES[0]` must equal
    /// `SHA256(WEIGHTED_THRESHOLD_POLICY_WASM)` — the allowlist entry
    /// `identify_weighted_threshold_policy` matches against.
    #[test]
    fn allowlist_entry_matches_embedded_wasm_sha256() {
        let digest: [u8; 32] = Sha256::digest(WEIGHTED_THRESHOLD_POLICY_WASM).into();
        assert_eq!(
            digest, WEIGHTED_THRESHOLD_POLICY_WASM_HASHES[0],
            "WEIGHTED_THRESHOLD_POLICY_WASM_HASHES[0] must equal the embedded WASM's sha256"
        );
    }

    /// The allowlist has exactly one entry (no legacy version to grandfather,
    /// unlike the two-entry simple-threshold allowlist).
    #[test]
    fn allowlist_has_exactly_one_entry() {
        assert_eq!(
            WEIGHTED_THRESHOLD_POLICY_WASM_HASHES.len(),
            1,
            "weighted-threshold allowlist must have exactly one entry"
        );
    }

    /// Asserts the embedded WASM starts with the WASM binary magic bytes
    /// `\0asm`.
    #[test]
    fn weighted_threshold_policy_wasm_has_correct_magic_bytes() {
        assert_eq!(
            &WEIGHTED_THRESHOLD_POLICY_WASM[..4],
            b"\0asm",
            "WEIGHTED_THRESHOLD_POLICY_WASM must start with WASM magic bytes"
        );
    }

    /// Asserts the embedded WASM byte length matches the value recorded in
    /// PROVENANCE.md.
    #[test]
    fn weighted_threshold_policy_wasm_size_matches_provenance() {
        assert_eq!(
            WEIGHTED_THRESHOLD_POLICY_WASM.len(),
            15_745,
            "vendored WASM byte count must match the value recorded in \
             vendor/oz-weighted-threshold-policy/v0.7.2/PROVENANCE.md"
        );
    }

    /// The install-param ScMap places `signer_weights` FIRST and `threshold`
    /// second (ascending Symbol-key order).
    #[test]
    fn install_param_scmap_signer_weights_first() {
        let scval = build_weighted_threshold_install_param(
            &[(
                WeightedThresholdSignerInput::Delegated {
                    g_strkey: SIMULATE_SENTINEL_G.to_owned(),
                },
                5,
            )],
            5,
        )
        .expect("build install param");

        let ScVal::Map(Some(ScMap(entries))) = &scval else {
            panic!("install param must be ScVal::Map");
        };
        assert_eq!(entries.len(), 2, "two struct fields");

        let ScVal::Symbol(k0) = &entries[0].key else {
            panic!("key0 must be Symbol")
        };
        assert_eq!(
            k0.to_utf8_string_lossy(),
            "signer_weights",
            "signer_weights must be first (0x73 < 0x74)"
        );

        let ScVal::Symbol(k1) = &entries[1].key else {
            panic!("key1 must be Symbol")
        };
        assert_eq!(k1.to_utf8_string_lossy(), "threshold");
        assert_eq!(entries[1].val, ScVal::U32(5));
    }

    /// A homogeneous all-Delegated signer set sorts by the Account-address
    /// suffix (the shared `"Delegated"` tag ties, so the tail decides).
    #[test]
    fn install_param_all_delegated_signers_sorted_by_address() {
        let low = ed25519_g_strkey(0x01);
        let high = ed25519_g_strkey(0xff);

        // Insert in descending order; the builder must re-sort ascending.
        let scval = build_weighted_threshold_install_param(
            &[
                (
                    WeightedThresholdSignerInput::Delegated {
                        g_strkey: high.clone(),
                    },
                    3,
                ),
                (WeightedThresholdSignerInput::Delegated { g_strkey: low }, 2),
            ],
            2,
        )
        .expect("build");

        let ScVal::Map(Some(ScMap(outer))) = &scval else {
            panic!("map")
        };
        let ScVal::Map(Some(ScMap(inner))) = &outer[0].val else {
            panic!("inner map")
        };
        assert_eq!(inner.len(), 2);

        let mut keys: Vec<ScVal> = inner.iter().map(|e| e.key.clone()).collect();
        let sorted = {
            let mut s = keys.clone();
            s.sort();
            s
        };
        assert_eq!(
            keys, sorted,
            "inner map keys must already be in canonical ScVal order"
        );
        // The 0x01-fill key sorts before the 0xff-fill key.
        keys.sort();
        assert_ne!(keys[0], keys[1]);
    }

    /// A heterogeneous Delegated + External signer set: all Delegated entries
    /// sort before all External entries (tag-Symbol comparison), matching the
    /// `build_multi_signer_auth_payload_scval` ordering rule.
    #[test]
    fn install_param_mixed_delegated_and_external_orders_delegated_first() {
        let delegated_g = ed25519_g_strkey(0x07);
        let verifier = verifier_sc_address(0x09);

        let scval = build_weighted_threshold_install_param(
            &[
                (
                    WeightedThresholdSignerInput::External {
                        verifier: verifier.clone(),
                        key_data: vec![0xAAu8; 32],
                    },
                    1,
                ),
                (
                    WeightedThresholdSignerInput::Delegated {
                        g_strkey: delegated_g,
                    },
                    2,
                ),
            ],
            2,
        )
        .expect("build");

        let ScVal::Map(Some(ScMap(outer))) = &scval else {
            panic!("map")
        };
        let ScVal::Map(Some(ScMap(inner))) = &outer[0].val else {
            panic!("inner map")
        };
        assert_eq!(inner.len(), 2);

        // Entry 0 must be the Delegated key: Vec([Symbol("Delegated"), Address]).
        let ScVal::Vec(Some(v0)) = &inner[0].key else {
            panic!("entry0 key must be Vec")
        };
        let ScVal::Symbol(tag0) = &v0[0] else {
            panic!("entry0 tag must be Symbol")
        };
        assert_eq!(tag0.to_utf8_string_lossy(), "Delegated");
        assert_eq!(inner[0].val, ScVal::U32(2));

        // Entry 1 must be the External key: Vec([Symbol("External"), Address, Bytes]).
        let ScVal::Vec(Some(v1)) = &inner[1].key else {
            panic!("entry1 key must be Vec")
        };
        let ScVal::Symbol(tag1) = &v1[0] else {
            panic!("entry1 tag must be Symbol")
        };
        assert_eq!(tag1.to_utf8_string_lossy(), "External");
        assert_eq!(inner[1].val, ScVal::U32(1));

        // Ordering is canonical: re-sorting is a no-op.
        let mut keys: Vec<ScVal> = inner.iter().map(|e| e.key.clone()).collect();
        let before = keys.clone();
        keys.sort();
        assert_eq!(keys, before, "mixed-kind keys must be in canonical order");
    }

    /// Empty `signer_weights` is refused before any XDR encoding.
    #[test]
    fn empty_signer_weights_is_refused() {
        let err = build_weighted_threshold_install_param(&[], 1)
            .expect_err("empty signer set must refuse");
        assert!(matches!(
            err,
            SaError::WeightedThresholdInstallRefused { .. }
        ));
    }

    /// `threshold == 0` is refused even with a valid non-empty signer set.
    #[test]
    fn zero_threshold_is_refused() {
        let err = build_weighted_threshold_install_param(
            &[(
                WeightedThresholdSignerInput::Delegated {
                    g_strkey: SIMULATE_SENTINEL_G.to_owned(),
                },
                5,
            )],
            0,
        )
        .expect_err("threshold 0 must refuse");
        assert!(matches!(
            err,
            SaError::WeightedThresholdInstallRefused { .. }
        ));
    }

    /// A zero-weight signer is refused.
    #[test]
    fn zero_weight_signer_is_refused() {
        let err = build_weighted_threshold_install_param(
            &[(
                WeightedThresholdSignerInput::Delegated {
                    g_strkey: SIMULATE_SENTINEL_G.to_owned(),
                },
                0,
            )],
            1,
        )
        .expect_err("zero weight must refuse");
        assert!(matches!(
            err,
            SaError::WeightedThresholdInstallRefused { .. }
        ));
    }

    /// `threshold` exceeding the sum of weights is refused.
    #[test]
    fn threshold_exceeding_weight_sum_is_refused() {
        let err = build_weighted_threshold_install_param(
            &[(
                WeightedThresholdSignerInput::Delegated {
                    g_strkey: SIMULATE_SENTINEL_G.to_owned(),
                },
                5,
            )],
            6,
        )
        .expect_err("threshold above sum must refuse");
        assert!(matches!(
            err,
            SaError::WeightedThresholdInstallRefused { .. }
        ));
    }

    /// A weight-sum overflow (two `u32::MAX` weights) is refused, not a
    /// silent wraparound.
    #[test]
    fn weight_sum_overflow_is_refused() {
        let low = ed25519_g_strkey(0x01);
        let high = ed25519_g_strkey(0xff);
        let err = build_weighted_threshold_install_param(
            &[
                (
                    WeightedThresholdSignerInput::Delegated { g_strkey: low },
                    u32::MAX,
                ),
                (
                    WeightedThresholdSignerInput::Delegated { g_strkey: high },
                    1,
                ),
            ],
            1,
        )
        .expect_err("overflowing weight sum must refuse");
        assert!(matches!(
            err,
            SaError::WeightedThresholdInstallRefused { .. }
        ));
    }

    /// `threshold` exactly equal to the weight sum is accepted (boundary).
    #[test]
    fn threshold_equal_to_weight_sum_is_accepted() {
        build_weighted_threshold_install_param(
            &[(
                WeightedThresholdSignerInput::Delegated {
                    g_strkey: SIMULATE_SENTINEL_G.to_owned(),
                },
                7,
            )],
            7,
        )
        .expect("threshold == sum must be accepted");
    }
}
