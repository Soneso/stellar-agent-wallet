//! `stellar-agent smart-account list-verifiers` — enumerate the verifier allowlist.
//!
//! Enumerates [`VERIFIER_ALLOWLIST`] and renders each entry with its
//! [`VerifierAuditStatus`] taxonomy. Default output is JSON.
//! Pass `--output table` for human-readable columns.
//!
//! # JSON envelope
//!
//! ```json
//! {
//!   "entries": [
//!     {
//!       "wasm_hash_first8": "9427e3dd",
//!       "wasm_hash_full": "9427e3dd71fb29115c6f0efdf2f703b32fec566b151421f991c3b4e248ebb1f7",
//!       "audit_status": "provisional",
//!       "attested_by": "OpenZeppelin",
//!       "attested_at": "2026-07-04"
//!     },
//!     {
//!       "wasm_hash_first8": "67800690",
//!       "wasm_hash_full": "678006909b50c6c365c033f137197e910d8396a2c68e9281327a2ed7dbf4b27a",
//!       "audit_status": "provisional",
//!       "attested_by": "OpenZeppelin",
//!       "attested_at": "2025-11-01"
//!     }
//!   ],
//!   "entry_count": 2
//! }
//! ```
//!
//! Index 0 is the canonical OZ WebAuthn-verifier v0.7.2 (the hash new deployments
//! use); index 1 is the legacy v0.7.1, still recognised for verifiers already
//! deployed on-chain.
//!
//! `Audited` entries carry `auditor` + `audited_at` (an external audit report).
//! `Provisional` entries carry `attested_by` + `attested_at` (a named-party
//! internal artefact review; no external audit report yet).
//! `Revoked` entries carry `revoked_at` + `reason`.
//! `Retired` entries carry `revoked_at` + `retired_at`; the long-form reason is
//! omitted per the 24-month rotation policy.
//! `Unaudited` entries carry no extra fields.
//!
//! # Mainnet refusal
//!
//! NOT applicable: `list-verifiers` is read-only (no signing, no submission).

use clap::Args;
use serde::{Deserialize, Serialize};

use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_smart_account::verifier_allowlist::{VERIFIER_ALLOWLIST, VerifierAuditStatus};

use crate::common::render::render_json;

// ── CLI Args ───────────────────────────────────────────────────────────────────

/// Arguments for `smart-account list-verifiers`.
#[derive(Debug, Args)]
#[non_exhaustive]
#[command(
    override_usage = "stellar-agent smart-account list-verifiers [--output {json|table}]",
    after_help = "Enumerates the compile-time VERIFIER_ALLOWLIST. \
                  Default output is JSON. \
                  Pass --output table for human-readable columns. \
                  The allowlist is compiled in (no network call)."
)]
pub struct ListVerifiersArgs {
    /// Output format: `json` (default) or `table`.
    ///
    /// `table` mode renders human-friendly columns. Default `json` for
    /// deterministic, scriptable output.
    #[arg(long, default_value = "json", value_name = "FORMAT")]
    pub output: OutputFormat,
}

// ── JSON envelope types ────────────────────────────────────────────────────────

/// JSON wire representation of one verifier allowlist entry.
///
/// The `audit_status` field carries the closed-set discriminator string
/// (`"audited"`, `"provisional"`, `"unaudited"`, `"revoked"`, `"retired"`).
/// Additional fields depend on the status:
///
/// - `"audited"`: `auditor` + `audited_at`.
/// - `"provisional"`: `attested_by` + `attested_at`.
/// - `"revoked"`: `revoked_at` + `reason`.
/// - `"retired"`: `revoked_at` + `retired_at` (reason omitted per rotation policy).
/// - `"unaudited"`: no extra fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ListVerifiersEntry {
    /// First-8-hex of the wasm hash (lower-case).
    pub wasm_hash_first8: String,

    /// Full 64-char lower-case hex of the wasm hash.
    pub wasm_hash_full: String,

    /// Closed-set audit status discriminator (`"audited"` / `"provisional"` /
    /// `"unaudited"` / `"revoked"` / `"retired"`).
    pub audit_status: String,

    /// Auditor name. Present only when `audit_status == "audited"`.
    ///
    /// Omitted (serialised as absent, not `null`) for all other statuses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auditor: Option<String>,

    /// ISO-8601 UTC audit date. Present only when `audit_status == "audited"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audited_at: Option<String>,

    /// Name of the party that performed the internal artefact review. Present
    /// only when `audit_status == "provisional"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attested_by: Option<String>,

    /// ISO-8601 UTC date of the internal artefact review. Present only when
    /// `audit_status == "provisional"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attested_at: Option<String>,

    /// ISO-8601 UTC revocation date. Present for `"revoked"` and `"retired"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,

    /// Short revocation reason. Present only for `"revoked"`.
    ///
    /// Omitted for `"retired"` per the rotation policy: the long-form reason
    /// drops out of the JSON envelope once the 24-month retention window
    /// elapses and the entry rotates to `Retired`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// ISO-8601 UTC retirement date. Present only for `"retired"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<String>,
}

/// Top-level JSON envelope for `smart-account list-verifiers`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ListVerifiersResult {
    /// All entries in [`VERIFIER_ALLOWLIST`] in index order.
    pub entries: Vec<ListVerifiersEntry>,

    /// Total number of entries.
    pub entry_count: usize,
}

impl ListVerifiersResult {
    /// Builds a [`ListVerifiersResult`] from the compile-time [`VERIFIER_ALLOWLIST`].
    #[must_use]
    pub fn from_allowlist() -> Self {
        let entries: Vec<ListVerifiersEntry> = VERIFIER_ALLOWLIST
            .iter()
            .map(|entry| {
                let wasm_hash_first8 = entry.wasm_hash[..4]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                let wasm_hash_full: String =
                    entry.wasm_hash.iter().map(|b| format!("{b:02x}")).collect();

                match &entry.audit_status {
                    VerifierAuditStatus::Audited {
                        auditor,
                        audited_at,
                    } => ListVerifiersEntry {
                        wasm_hash_first8,
                        wasm_hash_full,
                        audit_status: "audited".to_owned(),
                        auditor: Some((*auditor).to_owned()),
                        audited_at: Some((*audited_at).to_owned()),
                        attested_by: None,
                        attested_at: None,
                        revoked_at: None,
                        reason: None,
                        retired_at: None,
                    },
                    VerifierAuditStatus::Provisional {
                        attested_by,
                        attested_at,
                    } => ListVerifiersEntry {
                        wasm_hash_first8,
                        wasm_hash_full,
                        audit_status: "provisional".to_owned(),
                        auditor: None,
                        audited_at: None,
                        attested_by: Some((*attested_by).to_owned()),
                        attested_at: Some((*attested_at).to_owned()),
                        revoked_at: None,
                        reason: None,
                        retired_at: None,
                    },
                    VerifierAuditStatus::Unaudited => ListVerifiersEntry {
                        wasm_hash_first8,
                        wasm_hash_full,
                        audit_status: "unaudited".to_owned(),
                        auditor: None,
                        audited_at: None,
                        attested_by: None,
                        attested_at: None,
                        revoked_at: None,
                        reason: None,
                        retired_at: None,
                    },
                    VerifierAuditStatus::Revoked { revoked_at, reason } => ListVerifiersEntry {
                        wasm_hash_first8,
                        wasm_hash_full,
                        audit_status: "revoked".to_owned(),
                        auditor: None,
                        audited_at: None,
                        attested_by: None,
                        attested_at: None,
                        revoked_at: Some((*revoked_at).to_owned()),
                        reason: Some((*reason).to_owned()),
                        retired_at: None,
                    },
                    VerifierAuditStatus::Retired {
                        revoked_at,
                        retired_at,
                    } => ListVerifiersEntry {
                        wasm_hash_first8,
                        wasm_hash_full,
                        audit_status: "retired".to_owned(),
                        auditor: None,
                        audited_at: None,
                        attested_by: None,
                        attested_at: None,
                        revoked_at: Some((*revoked_at).to_owned()),
                        reason: None, // dropped for retired entries per the rotation policy
                        retired_at: Some((*retired_at).to_owned()),
                    },
                    // Forward-compat: future VerifierAuditStatus variants render
                    // with only wasm_hash fields populated (audit_status = "unknown").
                    _ => ListVerifiersEntry {
                        wasm_hash_first8,
                        wasm_hash_full,
                        audit_status: "unknown".to_owned(),
                        auditor: None,
                        audited_at: None,
                        attested_by: None,
                        attested_at: None,
                        revoked_at: None,
                        reason: None,
                        retired_at: None,
                    },
                }
            })
            .collect();

        let entry_count = entries.len();
        Self {
            entries,
            entry_count,
        }
    }

    /// Renders a human-readable table to stdout.
    ///
    /// Called when `--output table` is passed. Prints a header line followed
    /// by one row per entry.
    #[allow(
        clippy::print_stdout,
        clippy::print_literal,
        reason = "table output is the intended operator-visible CLI surface for --output table"
    )]
    pub fn render_table(&self) {
        println!("{:<18}  {:<12}  DETAIL", "WASM_HASH_FIRST8", "STATUS");
        println!("{}", "-".repeat(72));
        for entry in &self.entries {
            let detail = match entry.audit_status.as_str() {
                "audited" => format!(
                    "auditor={} audited_at={}",
                    entry.auditor.as_deref().unwrap_or(""),
                    entry.audited_at.as_deref().unwrap_or("")
                ),
                "provisional" => format!(
                    "attested_by={} attested_at={}",
                    entry.attested_by.as_deref().unwrap_or(""),
                    entry.attested_at.as_deref().unwrap_or("")
                ),
                "revoked" => format!(
                    "revoked_at={} reason={}",
                    entry.revoked_at.as_deref().unwrap_or(""),
                    entry.reason.as_deref().unwrap_or("")
                ),
                "retired" => format!(
                    "revoked_at={} retired_at={}",
                    entry.revoked_at.as_deref().unwrap_or(""),
                    entry.retired_at.as_deref().unwrap_or("")
                ),
                "unaudited" => "unaudited".to_owned(),
                other => other.to_owned(),
            };
            println!(
                "{:<18}  {:<12}  {}",
                entry.wasm_hash_first8, entry.audit_status, detail
            );
        }
    }
}

// ── Handler ────────────────────────────────────────────────────────────────────

/// Runs the `smart-account list-verifiers` subcommand.
///
/// Returns exit code `0` on success, `1` on error.
///
/// # Errors
///
/// Never returns `Err`. Errors are captured into the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &ListVerifiersArgs) -> i32 {
    let result = ListVerifiersResult::from_allowlist();

    match args.output {
        OutputFormat::Json => {
            let envelope = Envelope::ok(result);
            render_json(&envelope);
            0
        }
        OutputFormat::Table => {
            result.render_table();
            0
        }
        // Forward-compat: unknown future OutputFormat variants fall back to JSON.
        _ => {
            let envelope = Envelope::ok(result);
            render_json(&envelope);
            0
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]

    use super::*;

    #[test]
    fn list_verifiers_result_from_allowlist_has_correct_entry_count() {
        let result = ListVerifiersResult::from_allowlist();
        assert_eq!(
            result.entry_count,
            VERIFIER_ALLOWLIST.len(),
            "entry_count must match VERIFIER_ALLOWLIST.len()"
        );
        assert_eq!(result.entries.len(), result.entry_count);
    }

    #[test]
    fn list_verifiers_result_oz_canonical_and_legacy_entries_are_provisional() {
        let result = ListVerifiersResult::from_allowlist();
        assert!(
            result.entries.len() >= 2,
            "VERIFIER_ALLOWLIST must have the canonical v0.7.2 and legacy v0.7.1 entries"
        );

        // Index 0: canonical OZ WebAuthn verifier v0.7.2.
        let oz = &result.entries[0];
        assert_eq!(oz.audit_status, "provisional");
        assert_eq!(oz.wasm_hash_first8, "9427e3dd");
        assert_eq!(
            oz.wasm_hash_full,
            "9427e3dd71fb29115c6f0efdf2f703b32fec566b151421f991c3b4e248ebb1f7"
        );
        assert_eq!(oz.attested_by.as_deref(), Some("OpenZeppelin"));
        assert_eq!(oz.attested_at.as_deref(), Some("2026-07-04"));
        assert!(oz.auditor.is_none());
        assert!(oz.audited_at.is_none());
        assert!(oz.revoked_at.is_none());
        assert!(oz.reason.is_none());
        assert!(oz.retired_at.is_none());

        // Index 1: legacy OZ WebAuthn verifier v0.7.1 (still recognised).
        let legacy = &result.entries[1];
        assert_eq!(legacy.audit_status, "provisional");
        assert_eq!(legacy.wasm_hash_first8, "67800690");
        assert_eq!(
            legacy.wasm_hash_full,
            "678006909b50c6c365c033f137197e910d8396a2c68e9281327a2ed7dbf4b27a"
        );
        assert_eq!(legacy.attested_by.as_deref(), Some("OpenZeppelin"));
        assert_eq!(legacy.attested_at.as_deref(), Some("2025-11-01"));
        assert!(legacy.auditor.is_none());
        assert!(legacy.audited_at.is_none());
    }

    #[test]
    fn list_verifiers_result_json_round_trip() {
        let result = ListVerifiersResult::from_allowlist();
        let json = serde_json::to_string(&result).expect("serialise");
        let back: ListVerifiersResult = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(result, back, "JSON round-trip must preserve all fields");
    }

    #[test]
    fn list_verifiers_result_json_contains_entries_key() {
        let result = ListVerifiersResult::from_allowlist();
        let json = serde_json::to_string(&result).expect("serialise");
        assert!(
            json.contains("\"entries\""),
            "JSON must contain 'entries' key"
        );
        assert!(
            json.contains("\"entry_count\""),
            "JSON must contain 'entry_count' key"
        );
    }

    #[test]
    fn list_verifiers_entry_audited_wire_format() {
        // Validates the audited-variant JSON envelope wire shape.
        let entry = ListVerifiersEntry {
            wasm_hash_first8: "9427e3dd".to_owned(),
            wasm_hash_full: "9427e3dd71fb29115c6f0efdf2f703b32fec566b151421f991c3b4e248ebb1f7"
                .to_owned(),
            audit_status: "audited".to_owned(),
            auditor: Some("OpenZeppelin".to_owned()),
            audited_at: Some("2026-07-04".to_owned()),
            attested_by: None,
            attested_at: None,
            revoked_at: None,
            reason: None,
            retired_at: None,
        };
        let json = serde_json::to_string(&entry).expect("serialise");
        assert!(json.contains(r#""audit_status":"audited""#), "json={json}");
        assert!(json.contains(r#""auditor":"OpenZeppelin""#), "json={json}");
        assert!(json.contains(r#""audited_at":"2026-07-04""#), "json={json}");
        // attested_by / attested_at / revoked_at / reason / retired_at must be
        // absent (skip_serializing_if).
        assert!(
            !json.contains("attested_by"),
            "attested_by must be absent for audited: {json}"
        );
        assert!(
            !json.contains("attested_at"),
            "attested_at must be absent for audited: {json}"
        );
        assert!(
            !json.contains("revoked_at"),
            "revoked_at must be absent for audited: {json}"
        );
        assert!(
            !json.contains("\"reason\""),
            "reason must be absent for audited: {json}"
        );
        assert!(
            !json.contains("retired_at"),
            "retired_at must be absent for audited: {json}"
        );
    }

    #[test]
    fn list_verifiers_entry_provisional_wire_format() {
        // Validates the provisional-variant JSON envelope wire shape.
        let entry = ListVerifiersEntry {
            wasm_hash_first8: "9427e3dd".to_owned(),
            wasm_hash_full: "9427e3dd71fb29115c6f0efdf2f703b32fec566b151421f991c3b4e248ebb1f7"
                .to_owned(),
            audit_status: "provisional".to_owned(),
            auditor: None,
            audited_at: None,
            attested_by: Some("OpenZeppelin".to_owned()),
            attested_at: Some("2026-07-04".to_owned()),
            revoked_at: None,
            reason: None,
            retired_at: None,
        };
        let json = serde_json::to_string(&entry).expect("serialise");
        assert!(
            json.contains(r#""audit_status":"provisional""#),
            "json={json}"
        );
        assert!(
            json.contains(r#""attested_by":"OpenZeppelin""#),
            "json={json}"
        );
        assert!(
            json.contains(r#""attested_at":"2026-07-04""#),
            "json={json}"
        );
        // auditor / audited_at / revoked_at / reason / retired_at must be
        // absent (skip_serializing_if).
        assert!(
            !json.contains("\"auditor\""),
            "auditor must be absent for provisional: {json}"
        );
        assert!(
            !json.contains("audited_at"),
            "audited_at must be absent for provisional: {json}"
        );
        assert!(
            !json.contains("revoked_at"),
            "revoked_at must be absent for provisional: {json}"
        );
        assert!(
            !json.contains("\"reason\""),
            "reason must be absent for provisional: {json}"
        );
        assert!(
            !json.contains("retired_at"),
            "retired_at must be absent for provisional: {json}"
        );
    }

    #[test]
    fn list_verifiers_entry_revoked_wire_format() {
        let entry = ListVerifiersEntry {
            wasm_hash_first8: "aabbccdd".to_owned(),
            wasm_hash_full: "aabbccdd0011223344556677889900112233445566778899001122334455667788"
                .to_owned(),
            audit_status: "revoked".to_owned(),
            auditor: None,
            audited_at: None,
            attested_by: None,
            attested_at: None,
            revoked_at: Some("2026-03-01".to_owned()),
            reason: Some("CVE-2026-0001 bypass".to_owned()),
            retired_at: None,
        };
        let json = serde_json::to_string(&entry).expect("serialise");
        assert!(json.contains(r#""audit_status":"revoked""#), "json={json}");
        assert!(json.contains(r#""revoked_at":"2026-03-01""#), "json={json}");
        assert!(
            json.contains(r#""reason":"CVE-2026-0001 bypass""#),
            "json={json}"
        );
        assert!(
            !json.contains("\"auditor\""),
            "auditor must be absent for revoked: {json}"
        );
        assert!(
            !json.contains("attested_by"),
            "attested_by must be absent for revoked: {json}"
        );
        assert!(
            !json.contains("retired_at"),
            "retired_at must be absent for revoked: {json}"
        );
    }

    #[test]
    fn list_verifiers_entry_retired_wire_format() {
        // Per the rotation policy: `reason` field is omitted for retired entries.
        let entry = ListVerifiersEntry {
            wasm_hash_first8: "aabbccdd".to_owned(),
            wasm_hash_full: "aabbccdd0011223344556677889900112233445566778899001122334455667788"
                .to_owned(),
            audit_status: "retired".to_owned(),
            auditor: None,
            audited_at: None,
            attested_by: None,
            attested_at: None,
            revoked_at: Some("2026-03-01".to_owned()),
            reason: None,
            retired_at: Some("2028-03-01".to_owned()),
        };
        let json = serde_json::to_string(&entry).expect("serialise");
        assert!(json.contains(r#""audit_status":"retired""#), "json={json}");
        assert!(json.contains(r#""revoked_at":"2026-03-01""#), "json={json}");
        assert!(json.contains(r#""retired_at":"2028-03-01""#), "json={json}");
        // reason must be absent per rotation policy.
        assert!(
            !json.contains("\"reason\""),
            "reason must be absent for retired: {json}"
        );
        assert!(
            !json.contains("attested_by"),
            "attested_by must be absent for retired: {json}"
        );
    }

    #[test]
    fn list_verifiers_entry_unaudited_wire_format() {
        let entry = ListVerifiersEntry {
            wasm_hash_first8: "11223344".to_owned(),
            wasm_hash_full: "11223344556677889900aabbccddee0011223344556677889900aabbccddee00"
                .to_owned(),
            audit_status: "unaudited".to_owned(),
            auditor: None,
            audited_at: None,
            attested_by: None,
            attested_at: None,
            revoked_at: None,
            reason: None,
            retired_at: None,
        };
        let json = serde_json::to_string(&entry).expect("serialise");
        assert!(
            json.contains(r#""audit_status":"unaudited""#),
            "json={json}"
        );
        assert!(
            !json.contains("\"auditor\""),
            "auditor must be absent for unaudited: {json}"
        );
        assert!(
            !json.contains("attested_by"),
            "attested_by must be absent for unaudited: {json}"
        );
        assert!(
            !json.contains("\"reason\""),
            "reason must be absent for unaudited: {json}"
        );
    }
}
