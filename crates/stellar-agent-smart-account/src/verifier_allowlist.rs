//! Verifier allowlist with audit-status taxonomy.
//!
//! The allowlist encodes the compile-time set of approved verifier contract
//! wasm hashes the wallet trusts. Any verifier not on the allowlist requires
//! explicit operator approval.
//!
//! # Audit status taxonomy
//!
//! Each entry carries a [`VerifierAuditStatus`] that governs both install-time
//! gates and the startup advisory emitted by `run_startup_advisory`.
//! Entries never leave the allowlist immediately on revocation; the 24-month
//! retention policy ensures operators who are running older wallet releases still
//! receive the advisory before silently losing protection.
//!
//! # Wire format (JSON envelopes)
//!
//! [`VerifierAuditStatus`] serialises with `#[serde(rename_all = "snake_case",
//! tag = "kind")]` so the `kind` discriminator appears as `"audited"`,
//! `"unaudited"`, `"revoked"`, or `"retired"`. This is the canonical wire format
//! consumed by `smart-account list-verifiers --output json`.
//!
//! # 24-month retention
//!
//! `Revoked` entries persist for 24 months minimum, then rotate to `Retired`.
//! See `vendor/oz-webauthn-verifier/v0.7.2/PROVENANCE.md` for the retention policy.

use std::fmt;

use serde::Serialize;

/// Audit status of an entry in [`VERIFIER_ALLOWLIST`].
///
/// Closed four-value set with `#[non_exhaustive]` for future extension.
///
/// # Wire format (CLI envelope)
///
/// Snake_case discriminator via `#[serde(rename_all = "snake_case", tag = "kind")]`:
/// `"audited"` / `"unaudited"` / `"revoked"` / `"retired"`.
///
/// # Startup-advisory posture
///
/// `Revoked` and `Retired` entries both trigger the startup advisory emitted by
/// `run_startup_advisory`. The advisory is informational and non-fatal;
/// operators should run `smart-account migrate-verifier` to remediate.
///
/// # Serialise-only posture
///
/// `VerifierAuditStatus` derives `Serialize` but not `Deserialize`. The enum is
/// a compile-time type whose string fields are `&'static str`; serde's
/// `Deserialize` derive cannot satisfy the `'static` bound for borrowed strings
/// when driven from a `'de` lifetime. Since entries are only serialised for
/// `smart-account list-verifiers` output and never deserialised from external JSON,
/// `Serialize`-only is the correct posture — matching the `SaError` pattern in
/// this crate. If a future input path requires deserialization, introduce a
/// parallel owned type. `Serialize`-only (no `Deserialize`) is a defence-in-depth
/// security property — the typed allowlist cannot be reconstructed from external
/// input, blocking config-file-injection paths that could otherwise promote
/// `Revoked` entries to `Audited`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
#[non_exhaustive]
pub enum VerifierAuditStatus {
    /// Auditor-attested. Audit info encoded in `auditor` + `audited_at`.
    ///
    /// # Wire format
    ///
    /// Serialises as `{ "kind": "audited", "auditor": "...", "audited_at": "..." }`.
    Audited {
        /// Human-readable auditor name (e.g., `"OpenZeppelin"`, `"Trail of Bits"`,
        /// `"Veridise"`).
        auditor: &'static str,
        /// ISO-8601 UTC date of the audit report (e.g., `"2026-01-15"`).
        audited_at: &'static str,
    },

    /// No audit attached; operator-acknowledged risk required to install.
    ///
    /// # Wire format
    ///
    /// Serialises as `{ "kind": "unaudited" }`.
    Unaudited,

    /// Disclosed-vulnerable; an emergency wallet release flipped this from
    /// `Audited` to `Revoked`. Operator advisory fires on every CLI invocation
    /// until migrated.
    ///
    /// # Wire format
    ///
    /// Serialises as `{ "kind": "revoked", "revoked_at": "...", "reason": "..." }`.
    ///
    /// # 24-month retention
    ///
    /// A `Revoked` entry persists for at least 24 months before rotating to
    /// `Retired`. The `revoked_at` field is the canonical clock.
    Revoked {
        /// ISO-8601 UTC date the entry was flipped to revoked.
        revoked_at: &'static str,
        /// Short human-readable reason (e.g., `"CVE-2026-NNNN signature-verification bypass"`).
        reason: &'static str,
    },

    /// `Revoked` + 24-month retention elapsed. Still recognised by the startup-
    /// advisory check (operator advisory continues to fire), but the long-form
    /// audit-status text is dropped from `smart-account list-verifiers --json`
    /// after the 24-month rotation cadence.
    ///
    /// # Wire format
    ///
    /// Serialises as `{ "kind": "retired", "revoked_at": "...", "retired_at": "..." }`.
    /// The `Revoked` → `Retired` rotation drops the revocation reason from the
    /// typed value at the conversion site; the historical reason is preserved in
    /// the wallet changelog and the GHSA bulletin.
    Retired {
        /// ISO-8601 UTC date the entry was originally revoked.
        revoked_at: &'static str,
        /// ISO-8601 UTC date the entry was rotated from `Revoked` to `Retired`
        /// (24 months after `revoked_at`).
        retired_at: &'static str,
    },
}

impl fmt::Display for VerifierAuditStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Audited { .. } => f.write_str("audited"),
            Self::Unaudited => f.write_str("unaudited"),
            Self::Revoked { .. } => f.write_str("revoked"),
            Self::Retired { .. } => f.write_str("retired"),
        }
    }
}

/// One entry in the verifier allowlist.
///
/// `#[non_exhaustive]` for future field extension (e.g., attestation hash or
/// display_name fields that the `list-verifiers` CLI may surface).
///
/// # Serialise-only posture
///
/// `Deserialize` is intentionally omitted. `VerifierAllowlistEntry` is a
/// compile-time constant (`VERIFIER_ALLOWLIST`) whose inner
/// `VerifierAuditStatus` fields are `&'static str`. Serde's `Deserialize`
/// derive cannot satisfy the `'static` bound when driven from a `'de`
/// lifetime. Since entries are only serialised for `smart-account list-verifiers`
/// output and never deserialised from external JSON, `Serialize`-only matches
/// the `SaError` pattern in this crate. Introduce a parallel owned type if a
/// future input path requires deserialization. `Serialize`-only (no
/// `Deserialize`) is a defence-in-depth security property — the typed allowlist
/// cannot be reconstructed from external input, blocking config-file-injection
/// paths that could otherwise promote `Revoked` entries to `Audited`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct VerifierAllowlistEntry {
    /// SHA-256 of the verifier WASM (32 bytes, raw digest).
    ///
    /// The sole wasm-hash source for all callers. All consumers read the wasm
    /// hash from this typed field.
    pub wasm_hash: [u8; 32],

    /// Audit status. Drives both install-time gates AND the startup-advisory
    /// check in `run_startup_advisory`.
    pub audit_status: VerifierAuditStatus,
}

#[cfg(any(test, feature = "test-helpers"))]
impl VerifierAllowlistEntry {
    /// Constructs a synthetic `VerifierAllowlistEntry` for test fixtures.
    ///
    /// Available only under `#[cfg(any(test, feature = "test-helpers"))]`.
    /// Test-only public helpers must be feature-gated rather than using
    /// `#[doc(hidden)] pub fn`, which leaks symbols into public rustdoc.
    ///
    /// Used by `stellar-agent-cli`'s advisory trigger-path tests to inject
    /// synthetic `Revoked` / `Retired` entries without modifying the production
    /// `VERIFIER_ALLOWLIST` constant.
    #[must_use]
    pub fn new_for_test(wasm_hash: [u8; 32], audit_status: VerifierAuditStatus) -> Self {
        Self {
            wasm_hash,
            audit_status,
        }
    }
}

/// Workspace-shipped verifier allowlist.
///
/// Compile-time constant; no central server is consulted. Updates ship via
/// wallet patch releases; revoked entries fire startup advisories until
/// operators migrate via `smart-account migrate-verifier`.
///
/// # Current entries
///
/// Two production entries. Index 0 is the hash new verifier deployments upload
/// (`sha2::Sha256::digest(VERIFIER_WASM_FIXTURE)`); index 1 is the legacy hash,
/// still recognised for verifier contracts already deployed on-chain.
///
/// - Index 0: OZ `multisig-webauthn-verifier-example` v0.7.2.
///   - SHA-256: `9427e3dd71fb29115c6f0efdf2f703b32fec566b151421f991c3b4e248ebb1f7`
///   - OZ source SHA: `a9c42169000638da937577f592ebf61a7a3c94ca` (tag `v0.7.2`)
///   - PROVENANCE: `vendor/oz-webauthn-verifier/v0.7.2/PROVENANCE.md`
///   - Audit status: `Audited { auditor: "OpenZeppelin", audited_at: "2026-07-04" }`
///     — PROVISIONAL (OZ internal v0.7.2 artefact review date; not externally verified).
/// - Index 1: OZ `multisig-webauthn-verifier-example` v0.7.1 (legacy, still recognised).
///   - SHA-256: `678006909b50c6c365c033f137197e910d8396a2c68e9281327a2ed7dbf4b27a`
///   - OZ source SHA: `3f81125bed3114cc93f5fca6d13240082050269a` (tag `v0.7.1`)
///   - PROVENANCE: `vendor/oz-webauthn-verifier/v0.7.1/PROVENANCE.md`
///   - Audit status: `Audited { auditor: "OpenZeppelin", audited_at: "2025-11-01" }`
///     — PROVISIONAL (not externally verified; pending independent audit).
///
/// The ABI is unchanged between v0.7.1 and v0.7.2; the v0.7.2 bytes differ only
/// because of the soroban-sdk 26.1.0 bump. When a formal external audit date is
/// confirmed, update the corresponding `audited_at` date and PROVENANCE.md.
///
/// # 24-month retention
///
/// `Revoked` entries persist for 24 months minimum, then rotate to `Retired`.
///
/// # Extension
///
/// Append a new entry when a new audited verifier deployment is created, and keep
/// index 0 as the hash the deploy CLI currently uploads
/// (`Sha256::digest(VERIFIER_WASM_FIXTURE)`). Each addition requires an
/// operator-authorised PR with an updated `vendor/oz-webauthn-verifier/` artefact
/// and PROVENANCE.md.
pub const VERIFIER_ALLOWLIST: &[VerifierAllowlistEntry] = &[
    // Index 0: OZ multisig-webauthn-verifier-example v0.7.2 (canonical deploy verifier).
    //
    // Wasm hash: 9427e3dd71fb29115c6f0efdf2f703b32fec566b151421f991c3b4e248ebb1f7
    // (SHA-256 verified at vendor/oz-webauthn-verifier/v0.7.2/PROVENANCE.md).
    //
    // OZ source SHA: a9c42169000638da937577f592ebf61a7a3c94ca (tag v0.7.2).
    // OZ source file: examples/multisig-smart-account/webauthn-verifier/src/contract.rs
    //
    // Build: stellar contract build --package multisig-webauthn-verifier-example
    //        stellar-cli 25.2.0, rustc 1.96.0 stable, wasm32v1-none target.
    //
    // audited_at: PROVISIONAL "2026-07-04" (not externally verified; pending
    // independent audit) — represents the OZ internal v0.7.2 artefact review date.
    // Update when a formal external audit date is confirmed.
    VerifierAllowlistEntry {
        wasm_hash: [
            // SHA-256: 9427e3dd71fb29115c6f0efdf2f703b32fec566b151421f991c3b4e248ebb1f7
            // Canonical per vendor/oz-webauthn-verifier/v0.7.2/PROVENANCE.md.
            // Canonical hash is pinned in 3 sites; all must agree. See
            // verifier_identification.rs supply-chain test + verifier_allowlist.rs
            // anchor test + this const definition.
            0x94, 0x27, 0xe3, 0xdd, 0x71, 0xfb, 0x29, 0x11, 0x5c, 0x6f, 0x0e, 0xfd, 0xf2, 0xf7,
            0x03, 0xb3, 0x2f, 0xec, 0x56, 0x6b, 0x15, 0x14, 0x21, 0xf9, 0x91, 0xc3, 0xb4, 0xe2,
            0x48, 0xeb, 0xb1, 0xf7,
        ],
        audit_status: VerifierAuditStatus::Audited {
            auditor: "OpenZeppelin",
            audited_at: "2026-07-04",
        },
    },
    // Index 1: OZ multisig-webauthn-verifier-example v0.7.1 (legacy, still recognised).
    //
    // Wasm hash: 678006909b50c6c365c033f137197e910d8396a2c68e9281327a2ed7dbf4b27a
    // (SHA-256 verified at vendor/oz-webauthn-verifier/v0.7.1/PROVENANCE.md).
    //
    // OZ source SHA: 3f81125bed3114cc93f5fca6d13240082050269a (tag v0.7.1).
    // Still recognised for verifier contracts already deployed on-chain from the
    // v0.7.1 bytes; no longer deployed for new verifiers.
    //
    // audited_at: PROVISIONAL "2025-11-01" (not externally verified; pending
    // independent audit) — represents the OZ internal v0.7.1 artefact review date.
    VerifierAllowlistEntry {
        wasm_hash: [
            0x67, 0x80, 0x06, 0x90, 0x9b, 0x50, 0xc6, 0xc3, 0x65, 0xc0, 0x33, 0xf1, 0x37, 0x19,
            0x7e, 0x91, 0x0d, 0x83, 0x96, 0xa2, 0xc6, 0x8e, 0x92, 0x81, 0x32, 0x7a, 0x2e, 0xd7,
            0xdb, 0xf4, 0xb2, 0x7a,
        ],
        audit_status: VerifierAuditStatus::Audited {
            auditor: "OpenZeppelin",
            audited_at: "2025-11-01",
        },
    },
    #[cfg(any(test, feature = "test-helpers"))]
    VerifierAllowlistEntry {
        wasm_hash: [0xee; 32],
        audit_status: VerifierAuditStatus::Revoked {
            revoked_at: "2026-05-24",
            reason: "test-only revoked verifier fixture",
        },
    },
];

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    #![allow(clippy::expect_used, reason = "test-only")]

    use super::*;

    #[test]
    fn verifier_allowlist_closed_set_audit_status_count() {
        // Enumerate all variants; ensures any new variant added to
        // VerifierAuditStatus triggers a deliberate test update.
        let canonical: &[&str] = &["audited", "unaudited", "revoked", "retired"];
        let rendered: Vec<String> = [
            VerifierAuditStatus::Audited {
                auditor: "x",
                audited_at: "y",
            },
            VerifierAuditStatus::Unaudited,
            VerifierAuditStatus::Revoked {
                revoked_at: "x",
                reason: "y",
            },
            VerifierAuditStatus::Retired {
                revoked_at: "x",
                retired_at: "y",
            },
        ]
        .iter()
        .map(|v| v.to_string())
        .collect();
        let expected: Vec<String> = canonical.iter().map(|s| (*s).to_owned()).collect();
        assert_eq!(rendered, expected, "VerifierAuditStatus closed-set drift");
    }

    #[test]
    fn verifier_allowlist_has_canonical_oz_webauthn_verifier() {
        assert!(!VERIFIER_ALLOWLIST.is_empty());
        let oz = &VERIFIER_ALLOWLIST[0];
        assert!(matches!(
            oz.audit_status,
            VerifierAuditStatus::Audited { .. }
        ));
        // Hard-coded canonical hash per vendor/oz-webauthn-verifier/v0.7.2/PROVENANCE.md.
        // OZ source SHA: a9c42169000638da937577f592ebf61a7a3c94ca (tag v0.7.2).
        // SHA-256: 9427e3dd71fb29115c6f0efdf2f703b32fec566b151421f991c3b4e248ebb1f7
        //
        // Hard-coded byte array assertion: any future wasm_hash change is caught
        // here and must match vendor/oz-webauthn-verifier/v0.7.2/PROVENANCE.md.
        let canonical: [u8; 32] = [
            0x94, 0x27, 0xe3, 0xdd, 0x71, 0xfb, 0x29, 0x11, 0x5c, 0x6f, 0x0e, 0xfd, 0xf2, 0xf7,
            0x03, 0xb3, 0x2f, 0xec, 0x56, 0x6b, 0x15, 0x14, 0x21, 0xf9, 0x91, 0xc3, 0xb4, 0xe2,
            0x48, 0xeb, 0xb1, 0xf7,
        ];
        assert_eq!(
            oz.wasm_hash, canonical,
            "VERIFIER_ALLOWLIST[0].wasm_hash does not match the canonical OZ v0.7.2 hash; \
             update verifier_allowlist.rs to match PROVENANCE.md \
             (vendor/oz-webauthn-verifier/v0.7.2/PROVENANCE.md)."
        );
    }

    #[test]
    fn verifier_allowlist_retains_legacy_v0_7_1_verifier() {
        // Guards the index-reorder: index 0 is the current v0.7.2 deploy hash and
        // index 1 must remain the v0.7.1 hash so verifier contracts already
        // deployed on-chain keep passing identification. A silent loss of the
        // legacy entry fails here.
        assert!(
            VERIFIER_ALLOWLIST.len() >= 2,
            "VERIFIER_ALLOWLIST must retain the legacy v0.7.1 verifier at index 1"
        );
        let legacy = &VERIFIER_ALLOWLIST[1];
        assert!(matches!(
            legacy.audit_status,
            VerifierAuditStatus::Audited { .. }
        ));
        // Hard-coded canonical v0.7.1 hash per vendor/oz-webauthn-verifier/v0.7.1/PROVENANCE.md.
        // SHA-256: 678006909b50c6c365c033f137197e910d8396a2c68e9281327a2ed7dbf4b27a
        let legacy_v0_7_1: [u8; 32] = [
            0x67, 0x80, 0x06, 0x90, 0x9b, 0x50, 0xc6, 0xc3, 0x65, 0xc0, 0x33, 0xf1, 0x37, 0x19,
            0x7e, 0x91, 0x0d, 0x83, 0x96, 0xa2, 0xc6, 0x8e, 0x92, 0x81, 0x32, 0x7a, 0x2e, 0xd7,
            0xdb, 0xf4, 0xb2, 0x7a,
        ];
        assert_eq!(
            legacy.wasm_hash, legacy_v0_7_1,
            "VERIFIER_ALLOWLIST[1].wasm_hash must remain the OZ v0.7.1 legacy hash \
             (vendor/oz-webauthn-verifier/v0.7.1/PROVENANCE.md); verifier contracts \
             already deployed on-chain rely on it staying recognised."
        );
    }

    #[test]
    fn verifier_allowlist_serde_wire_format_pin() {
        // `VerifierAuditStatus` is `Serialize`-only (`&'static str` fields are
        // incompatible with serde `Deserialize`'s `'de` lifetime — see type-level
        // rustdoc; same pattern as `SaError`). The "round-trip" here serialises
        // each variant and verifies the produced JSON value matches the expected
        // structure, locking the wire format without needing `Deserialize`.

        struct Case {
            status: VerifierAuditStatus,
            expected_kind: &'static str,
        }
        let cases = [
            Case {
                status: VerifierAuditStatus::Audited {
                    auditor: "OpenZeppelin",
                    audited_at: "2025-11-01",
                },
                expected_kind: "audited",
            },
            Case {
                status: VerifierAuditStatus::Unaudited,
                expected_kind: "unaudited",
            },
            Case {
                status: VerifierAuditStatus::Revoked {
                    revoked_at: "2026-03-01",
                    reason: "test-cve",
                },
                expected_kind: "revoked",
            },
            Case {
                status: VerifierAuditStatus::Retired {
                    revoked_at: "2026-03-01",
                    retired_at: "2028-03-01",
                },
                expected_kind: "retired",
            },
        ];
        for case in &cases {
            let json = serde_json::to_string(&case.status).expect("serialise status");
            let val: serde_json::Value = serde_json::from_str(&json).expect("parse JSON value");
            assert_eq!(
                val["kind"].as_str(),
                Some(case.expected_kind),
                "kind discriminator mismatch for status={} json={json}",
                case.status,
            );
        }
    }

    #[test]
    fn verifier_allowlist_no_duplicate_wasm_hashes() {
        // Closed-set discipline: duplicate wasm_hash values would silently allow
        // an operator to install the same verifier twice with different audit statuses.
        let mut hashes: Vec<[u8; 32]> = VERIFIER_ALLOWLIST.iter().map(|e| e.wasm_hash).collect();
        let before = hashes.len();
        hashes.sort_unstable();
        hashes.dedup();
        assert_eq!(
            hashes.len(),
            before,
            "VERIFIER_ALLOWLIST contains duplicate wasm_hash entries"
        );
    }

    #[test]
    fn verifier_allowlist_has_at_least_one_audited_entry() {
        // An empty allowlist or an all-unaudited allowlist would silently disable
        // enforcement. Require at least one Audited entry.
        let audited_count = VERIFIER_ALLOWLIST
            .iter()
            .filter(|e| matches!(e.audit_status, VerifierAuditStatus::Audited { .. }))
            .count();
        assert!(
            audited_count >= 1,
            "VERIFIER_ALLOWLIST must contain at least one Audited entry; \
             an all-unaudited allowlist silently disables enforcement"
        );
    }

    #[test]
    fn verifier_allowlist_audited_variant_wire_format() {
        // Pin the exact JSON wire format so a future serde attribute change is
        // caught immediately.
        let status = VerifierAuditStatus::Audited {
            auditor: "OpenZeppelin",
            audited_at: "2025-11-01",
        };
        let json = serde_json::to_string(&status).expect("serialise");
        // Must contain kind discriminator and both fields.
        assert!(json.contains(r#""kind":"audited""#), "json={json}");
        assert!(json.contains(r#""auditor":"OpenZeppelin""#), "json={json}");
        assert!(json.contains(r#""audited_at":"2025-11-01""#), "json={json}");
    }

    #[test]
    fn verifier_allowlist_revoked_variant_wire_format() {
        let status = VerifierAuditStatus::Revoked {
            revoked_at: "2026-03-01",
            reason: "CVE-2026-0001 bypass",
        };
        let json = serde_json::to_string(&status).expect("serialise");
        assert!(json.contains(r#""kind":"revoked""#), "json={json}");
        assert!(json.contains(r#""revoked_at":"2026-03-01""#), "json={json}");
        assert!(
            json.contains(r#""reason":"CVE-2026-0001 bypass""#),
            "json={json}"
        );
    }

    #[test]
    fn verifier_allowlist_retired_variant_wire_format() {
        let status = VerifierAuditStatus::Retired {
            revoked_at: "2026-03-01",
            retired_at: "2028-03-01",
        };
        let json = serde_json::to_string(&status).expect("serialise");
        assert!(json.contains(r#""kind":"retired""#), "json={json}");
        assert!(json.contains(r#""revoked_at":"2026-03-01""#), "json={json}");
        assert!(json.contains(r#""retired_at":"2028-03-01""#), "json={json}");
    }
}
