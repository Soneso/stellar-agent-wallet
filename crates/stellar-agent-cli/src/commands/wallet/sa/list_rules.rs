//! `stellar-agent wallet sa list-rules` — enumerate active context rules on a smart account.
//!
//! Scans the OZ on-chain `[0, max_scan_id)` rule-ID space for a smart account and
//! returns every active context rule in monotonic rule-ID order.  The scan
//! early-exits when `active_count` rules are collected and treats
//! `SmartAccountError::ContextRuleNotFound` (discriminant 3000) as a sparse-gap
//! signal so accounts with deleted rules are handled correctly.
//!
//! # Flags
//!
//! | Flag | Required | Description |
//! |------|----------|-------------|
//! | `--account <C_STRKEY>` | yes | Smart-account contract address. |
//! | `--rpc-url <URL>` | no | Soroban RPC endpoint (default: testnet). |
//! | `--secondary-rpc-url <URL>` | no | Secondary RPC for two-RPC consultation. |
//! | `--network {testnet\|mainnet}` | no | Target network (default: `testnet`). |
//! | `--profile <NAME>` | no | Profile name for config lookup. |
//! | `--max-scan-id <N>` | no | Override the upper scan bound (`1..=10_000`). |
//! | `--output {json\|table}` | no | Output format (default: `json`). Table mode deferred. |
//!
//! # JSON envelope
//!
//! ```json
//! {
//!   "rules": [
//!     {
//!       "rule_id": 0,
//!       "name": "my-rule",
//!       "context_type_label": "default",
//!       "signer_count": 1,
//!       "policy_count": 0,
//!       "valid_until": null
//!     }
//!   ],
//!   "active_count": 1,
//!   "scanned_id_range": { "start": 0, "end": 1 },
//!   "rules_skipped": 0,
//!   "gaps_seen": 0,
//!   "audit_log_missing": []
//! }
//! ```
//!
//! # Read-only behaviour
//!
//! No signer source required.  The command issues only `simulate_transaction`
//! calls via the Soroban RPC; no transactions are submitted.  It issues zero
//! outbound HTTP to any non-RPC URL during enumeration.
//!
//! # Mainnet refusal
//!
//! NOT applicable: `list-rules` is read-only.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Args;
use serde::{Deserialize, Serialize};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{ValidationError, WalletError};
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_core::profile::loader;
/// Well-known interop deployer G-strkey derived from the publicly-documented
/// SHA256("openzeppelin-smart-account-kit") seed.  Used as a funded testnet
/// simulation source when `--source-account` is not supplied.
///
/// This is a public, non-secret address; it carries no sensitive material.
const INTEROP_DEPLOYER_G: &str = "GAAH4OT36RRCCAGKARGPN2HLHT2NOBVFHO4GUHA6CF7UKQ4MMV24WQ4N";
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleManager, ContextRuleManagerConfig, DEFAULT_MAX_SCAN_ID, UPPER_BOUND_MAX_SCAN_ID,
    parse_c_strkey_to_smart_account,
};
use tracing::{info, warn};

use crate::commands::wallet::common::{network_to_chain_id, open_audit_writer};
use crate::common::network::TargetNetwork;
use crate::common::render::render_json;
use crate::common::resolve_profile_name;

// ── Constants ──────────────────────────────────────────────────────────────────

/// Default Soroban RPC endpoint for Stellar testnet.
const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";

/// Default submission-equivalent timeout (simulate only) in seconds.
const DEFAULT_TIMEOUT_SECONDS: u64 = 60;

// ── CLI Args ───────────────────────────────────────────────────────────────────

/// Arguments for `wallet sa list-rules`.
///
/// Read-only: no signer-source flags required.  The command enumerates active
/// context rules on the smart account at `--account` via on-chain simulation.
#[derive(Debug, Args)]
#[non_exhaustive]
#[command(
    override_usage = "stellar-agent wallet sa list-rules \
        --account <C_STRKEY> [--rpc-url <URL>] [--network {testnet|mainnet}] \
        [--max-scan-id <N>] [--output {json|table}]",
    after_help = "Enumerates all active context rules on the smart account by scanning \
                  the on-chain OZ rule-ID space [0, max_scan_id). \
                  Default output is JSON. \
                  No signing required (read-only). \
                  max-scan-id defaults to the profile value if set, else 50. \
                  Values above 10000 are rejected at parse time."
)]
pub struct ListRulesArgs {
    /// Smart-account contract C-strkey to query.
    ///
    /// Must be a valid Stellar contract address (`C...` strkey).
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub account: String,

    /// Soroban simulation source account G-strkey.
    ///
    /// Used as the source account for the `simulate_transaction` RPC calls.
    /// No signing is performed against this account; it is queried for its
    /// current sequence number to assemble a valid transaction envelope for
    /// simulation.
    ///
    /// On testnet, defaults to the SAK interop well-known deployer G-strkey
    /// (which is always funded).  On mainnet, this flag is required; passing
    /// any funded mainnet account is sufficient — the account is not debited.
    #[arg(long, value_name = "G_STRKEY")]
    pub source_account: Option<String>,

    /// Primary Soroban RPC endpoint.
    ///
    /// Defaults to the Stellar testnet RPC URL.  Override for mainnet or a
    /// custom deployment.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Secondary Soroban RPC URL for two-RPC consultation.
    ///
    /// Defaults to `--rpc-url` (degrades to single-RPC where primary and
    /// secondary trivially agree).
    #[arg(long, value_name = "URL")]
    pub secondary_rpc_url: Option<String>,

    /// Target network: `testnet` (default) or `mainnet`.
    ///
    /// Used to derive the correct network passphrase for transaction simulation.
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Profile name for config/audit-log lookup.
    ///
    /// Defaults to the value of `STELLAR_AGENT_PROFILE` env var, or `"default"`.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Optional override for the rule-ID scan upper bound.
    ///
    /// When set, overrides both the profile's `smart_account_max_context_rule_scan_id`
    /// and the compiled-in default of 50.  Must be in `1..=10_000`; values outside
    /// this range are rejected at parse time.
    ///
    /// Raise this value when the smart account has had more than 50 rules
    /// historically installed (including deletions), because deleted rules leave
    /// gaps in the monotonic ID space.
    #[arg(
        long,
        value_name = "N",
        value_parser = parse_max_scan_id
    )]
    pub max_scan_id: Option<u32>,

    /// Simulation timeout in seconds.
    ///
    /// Covers the full enumeration (not per-rule).  Increase for accounts with
    /// many rules on a slow RPC.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,

    /// Output format: `json` (default) or `table`.
    ///
    /// Table mode is deferred (`table` accepted by the flag parser but renders
    /// the same JSON envelope until the human-readable table renderer ships).
    #[arg(long, default_value = "json", value_name = "FORMAT")]
    pub output: OutputFormat,
}

/// Clap value-parser for `--max-scan-id`.
///
/// Accepts values in `[1, UPPER_BOUND_MAX_SCAN_ID]`.  Values of `0` or above
/// `UPPER_BOUND_MAX_SCAN_ID` (`10_000`) are rejected with a descriptive error
/// so the user sees the rejection at argument-parse time rather than at
/// command-runtime.
///
/// # Errors
///
/// Returns a [`String`] error message when the parsed value is out of range.
fn parse_max_scan_id(s: &str) -> Result<u32, String> {
    let n: u32 = s
        .parse()
        .map_err(|_| format!("--max-scan-id: expected an integer, got '{s}'"))?;
    if n == 0 {
        return Err("--max-scan-id must be >= 1 (0 would scan no rule IDs)".to_owned());
    }
    if n > UPPER_BOUND_MAX_SCAN_ID {
        return Err(format!(
            "--max-scan-id {n} exceeds the safety cap of {UPPER_BOUND_MAX_SCAN_ID}; \
             raise this cap via UPPER_BOUND_MAX_SCAN_ID if truly needed"
        ));
    }
    Ok(n)
}

// ── JSON envelope types ────────────────────────────────────────────────────────

/// One active context rule in the `wallet sa list-rules` JSON envelope.
///
/// Fields mirror [`stellar_agent_smart_account::managers::rules::ContextRuleSummary`];
/// this is the wire-level projection for the CLI envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ListRulesEntry {
    /// Monotonically-allocated on-chain rule ID (`NextId`, never recycled).
    pub rule_id: u32,

    /// Operator-visible rule name.
    pub name: String,

    /// Context type label: `"default"`, `"call_contract"`, or `"create_contract"`.
    pub context_type_label: String,

    /// Number of signers attached to the rule.
    pub signer_count: u32,

    /// Number of policies attached to the rule.
    pub policy_count: u32,

    /// Optional ledger sequence at which the rule expires.
    ///
    /// `null` means the rule is permanent (no expiry).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u32>,
}

/// Scanned rule-ID range reported in the envelope.
///
/// `start` is always `0` (scan begins at ID 0 per the OZ `NextId` allocation
/// contract). `end` is one-past-the-last probed ID — the first ID that was NOT
/// probed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ScannedIdRange {
    /// First rule ID probed (always `0`).
    pub start: u32,

    /// One-past-the-last rule ID probed.
    ///
    /// For a scan that early-exited cleanly after collecting all `active_count`
    /// rules, this equals the last probed rule ID + 1 (i.e. the ID that caused
    /// the early-exit condition to fire, which was NOT probed).  For a scan that
    /// exhausted `max_scan_id` this equals `max_scan_id`.
    pub end: u32,
}

/// Top-level JSON envelope for `wallet sa list-rules`.
///
/// Carries the active rules plus the `rules_skipped` and `audit_log_missing`
/// defence-in-depth fields from [`ActiveContextRuleEnumeration`].
///
/// [`ActiveContextRuleEnumeration`]: stellar_agent_smart_account::managers::rules::ActiveContextRuleEnumeration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ListRulesResult {
    /// Active rules in ascending `rule_id` order.
    pub rules: Vec<ListRulesEntry>,

    /// Number of active rules as reported by the on-chain `Count` storage
    /// entry at the start of the scan.
    ///
    /// Equals `rules.len()` on a clean enumeration.  When
    /// `active_count > rules.len() + rules_skipped + gaps_seen` the on-chain
    /// count disagrees with the observed scan — possible RPC data
    /// suppression or audit-log desync.
    pub active_count: u32,

    /// ID range probed during the scan.
    pub scanned_id_range: ScannedIdRange,

    /// Number of rule IDs that returned a transient RPC error and were
    /// defensively skipped (anomalous skips).
    ///
    /// Does NOT include legitimate sparse-gap signals (`ContextRuleNotFound`
    /// `Ok(None)` from `get_rule`) — those are counted in `gaps_seen`.
    /// Surfaces operator-actionable anomalies only.
    pub rules_skipped: u32,

    /// Number of rule IDs that returned `ContextRuleNotFound` during the
    /// scan — legitimate sparse-gap signals from previously-deleted rules.
    ///
    /// Normal for any account that has had rules deleted: the OZ contract
    /// retains the monotonic `NextId` counter but decrements `Count`,
    /// leaving holes in the ID space.  Surfaced separately so operators
    /// can distinguish expected sparse-gap observations from anomalous
    /// `rules_skipped` events.
    pub gaps_seen: u32,

    /// Rule IDs the local audit log records as installed but the on-chain scan
    /// did not return.
    ///
    /// Non-empty values indicate a malicious RPC drop or audit-log desync.
    /// Empty on a normal enumeration.
    pub audit_log_missing: Vec<u32>,
}

// ── Handler ────────────────────────────────────────────────────────────────────

/// Runs `wallet sa list-rules`.
///
/// Returns exit code `0` on success, `1` on any error.  All errors are
/// captured into the JSON envelope; this function never panics.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &ListRulesArgs) -> i32 {
    let profile_name = resolve_profile_name(args.profile.as_deref());

    // ── Parse --account C-strkey ──────────────────────────────────────────────
    let smart_account = match parse_c_strkey_to_smart_account(&args.account) {
        Ok(a) => a,
        Err(e) => {
            return emit_error(&WalletError::Validation(ValidationError::AddressInvalid {
                input: format!("--account: {e}"),
            }));
        }
    };

    // ── Resolve max_scan_id ───────────────────────────────────────────────────
    // Priority (highest first):
    //   1. --max-scan-id CLI flag (already range-validated by clap value-parser).
    //   2. profile.smart_account_max_context_rule_scan_id (validated at profile-load).
    //   3. DEFAULT_MAX_SCAN_ID (50).
    let max_scan_id = resolve_max_scan_id(args, &profile_name);

    // ── Open audit writer for audit-log cross-check ───────────────────────────
    let (audit_writer, _audit_log_path): (Arc<Mutex<AuditWriter>>, _) =
        match open_audit_writer(&profile_name) {
            Ok(pair) => pair,
            Err(e) => return emit_error(&e),
        };

    // ── Build ContextRuleManager (read-only, no signer required) ─────────────
    // For read-only simulation the manager uses a single RPC URL.
    // `--secondary-rpc-url` is accepted in the Args struct for future use and
    // for consistency with other sa subcommands. Log a warn! when the operator
    // supplies it, so they know it is currently a no-op.
    if args.secondary_rpc_url.is_some() {
        warn!(
            "--secondary-rpc-url is accepted for forward compatibility but is \
             not consulted by `wallet sa list-rules`; the primary RPC \
             is the only data source"
        );
    }
    // Log a warn! when the operator requests `--output table` so the JSON
    // fallback does not surprise them. The table renderer is not yet shipped.
    if matches!(args.output, OutputFormat::Table) {
        warn!(
            "--output table is accepted for forward compatibility but only the \
             JSON renderer is shipped; falling back to JSON"
        );
    }
    let timeout = Duration::from_secs(args.timeout_seconds);
    let chain_id = network_to_chain_id(args.network).to_owned();

    let config = ContextRuleManagerConfig::new(
        args.rpc_url.clone(),
        args.network.passphrase().to_owned(),
        timeout,
        chain_id.clone(),
    )
    .with_audit_writer(Arc::clone(&audit_writer));

    let manager = match ContextRuleManager::new(config) {
        Ok(m) => m,
        Err(e) => {
            return emit_error(&WalletError::Validation(ValidationError::AddressInvalid {
                input: format!("ContextRuleManager construction: {e}"),
            }));
        }
    };

    info!(
        account = redact_strkey_first5_last5(&args.account),
        max_scan_id,
        network = %args.network,
        chain_id = %chain_id,
        "wallet sa list-rules: enumerating active context rules"
    );

    // ── Resolve source account for Soroban simulation ─────────────────────────
    // `list_active_context_rules` needs a funded G-strkey account to use as the
    // simulation source (for sequence-number lookup only — no signing performed).
    // Resolution priority:
    //   1. --source-account explicit flag.
    //   2. testnet: well-known interop deployer (always funded on testnet).
    //   3. mainnet: require --source-account (no safe default exists).
    let source_account_strkey = match &args.source_account {
        Some(g) => g.clone(),
        None => {
            if args.network == TargetNetwork::Mainnet {
                return emit_error(&WalletError::Validation(ValidationError::AddressInvalid {
                    input: "--source-account is required for mainnet enumeration; \
                             pass a funded G-strkey (no signing is performed against it)"
                        .to_owned(),
                }));
            }
            // Testnet: use the well-known interop deployer as the simulation source.
            INTEROP_DEPLOYER_G.to_owned()
        }
    };

    // ── Run enumeration ───────────────────────────────────────────────────────
    let enumeration = match manager
        .list_active_context_rules(smart_account, &source_account_strkey, max_scan_id)
        .await
    {
        Ok(e) => e,
        Err(e) => {
            return emit_sa_error(&e);
        }
    };

    // ── Build result envelope ─────────────────────────────────────────────────
    // Capture scalar fields before the enumeration is partially moved into
    // the result struct below.  The on-chain `Count` is surfaced as
    // `active_count` rather than `rules.len()` so operators can detect
    // on-chain-vs-observed discrepancies (e.g. malicious-RPC drops).
    // `rules_skipped` surfaces ANOMALOUS skips only; legitimate sparse gaps
    // are in `gaps_seen`.
    //
    // invariant: enumeration.rules_skipped + enumeration.gaps_seen <=
    // UPPER_BOUND_MAX_SCAN_ID (10_000) — bounded by the scan loop in
    // `list_active_context_rules`. `unwrap_or(u32::MAX)` is unreachable in
    // production but defends against future bound-lift refactors.
    let active_count = enumeration.active_count_on_chain;
    let rules_skipped = u32::try_from(enumeration.rules_skipped).unwrap_or(u32::MAX);
    let gaps_seen = u32::try_from(enumeration.gaps_seen).unwrap_or(u32::MAX);
    let scanned_id_range_end = enumeration.scanned_id_range_end;
    let audit_log_missing_count = enumeration.audit_log_missing.len();

    let rules: Vec<ListRulesEntry> = enumeration
        .rules
        .into_iter()
        .map(|r| ListRulesEntry {
            rule_id: r.rule_id,
            name: r.name,
            context_type_label: r.context_type_label.to_owned(),
            signer_count: r.signer_count,
            policy_count: r.policy_count,
            valid_until: r.valid_until,
        })
        .collect();

    let result = ListRulesResult {
        rules,
        active_count,
        scanned_id_range: ScannedIdRange {
            start: 0,
            end: scanned_id_range_end,
        },
        rules_skipped,
        gaps_seen,
        audit_log_missing: enumeration.audit_log_missing,
    };

    info!(
        active_count,
        scanned_id_range_end,
        rules_skipped,
        audit_log_missing_count,
        "wallet sa list-rules: enumeration complete"
    );

    let envelope = Envelope::ok(result);
    render_json(&envelope);
    0
}

/// Resolves the effective `max_scan_id` from CLI flag, profile, or compiled default.
///
/// Priority:
/// 1. `--max-scan-id` CLI flag (already range-validated by [`parse_max_scan_id`]).
/// 2. `profile.smart_account_max_context_rule_scan_id` (validated at profile-load
///    time against `UPPER_BOUND_MAX_SCAN_ID`).
/// 3. [`DEFAULT_MAX_SCAN_ID`] (50).
///
/// Profile load errors are logged and the default is used; this keeps the
/// command usable when no profile exists (e.g. CI/testnet-only usage).
fn resolve_max_scan_id(args: &ListRulesArgs, profile_name: &str) -> u32 {
    // Priority 1: explicit CLI flag.
    if let Some(n) = args.max_scan_id {
        return n;
    }

    // Priority 2: profile field (validated at profile-load time).
    match loader::load(profile_name, None) {
        Ok(profile) => {
            if let Some(n) = profile.smart_account_max_context_rule_scan_id {
                return n;
            }
        }
        Err(e) => {
            tracing::debug!(
                profile = %profile_name,
                error = %e,
                "wallet sa list-rules: profile load for max_scan_id resolution failed; \
                 using DEFAULT_MAX_SCAN_ID"
            );
        }
    }

    // Priority 3: compiled-in default.
    DEFAULT_MAX_SCAN_ID
}

// ── Error emission helpers ─────────────────────────────────────────────────────

/// Serialises a [`WalletError`] into a JSON envelope and prints to stdout.
///
/// Returns exit code `1`.
fn emit_error(e: &WalletError) -> i32 {
    let envelope: Envelope<()> = Envelope::err(e);
    render_json(&envelope);
    1
}

/// Serialises a [`SaError`] into a JSON envelope and prints to stdout.
///
/// Returns exit code `1`.
fn emit_sa_error(e: &SaError) -> i32 {
    let wallet_err = WalletError::SmartAccount {
        wire_code: e.wire_code(),
        message: e.to_string(),
    };
    emit_error(&wallet_err)
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

    // ── parse_max_scan_id ──────────────────────────────────────────────────────

    #[test]
    fn parse_max_scan_id_rejects_zero() {
        let err = parse_max_scan_id("0").expect_err("0 must be rejected");
        assert!(
            err.contains("must be >= 1"),
            "error must mention the >= 1 constraint; got: {err}"
        );
    }

    #[test]
    fn parse_max_scan_id_accepts_one() {
        assert_eq!(parse_max_scan_id("1").unwrap(), 1);
    }

    #[test]
    fn parse_max_scan_id_accepts_upper_bound() {
        let n = parse_max_scan_id(&UPPER_BOUND_MAX_SCAN_ID.to_string()).unwrap();
        assert_eq!(n, UPPER_BOUND_MAX_SCAN_ID);
    }

    #[test]
    fn parse_max_scan_id_rejects_above_upper_bound() {
        let above = (UPPER_BOUND_MAX_SCAN_ID + 1).to_string();
        let err = parse_max_scan_id(&above).expect_err("value above cap must be rejected");
        assert!(
            err.contains("exceeds the safety cap"),
            "error must mention the safety cap; got: {err}"
        );
    }

    #[test]
    fn parse_max_scan_id_rejects_non_integer() {
        let err = parse_max_scan_id("abc").expect_err("non-integer must be rejected");
        assert!(
            err.contains("expected an integer"),
            "error must mention the parse failure; got: {err}"
        );
    }

    // ── JSON envelope shape ────────────────────────────────────────────────────

    #[test]
    fn list_rules_result_json_round_trip() {
        let result = ListRulesResult {
            rules: vec![ListRulesEntry {
                rule_id: 0,
                name: "boot-rule".to_owned(),
                context_type_label: "default".to_owned(),
                signer_count: 1,
                policy_count: 0,
                valid_until: None,
            }],
            active_count: 1,
            scanned_id_range: ScannedIdRange { start: 0, end: 1 },
            rules_skipped: 0,
            gaps_seen: 0,
            audit_log_missing: vec![],
        };

        let json = serde_json::to_string(&result).expect("serialise");
        let back: ListRulesResult = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(result, back, "JSON round-trip must preserve all fields");
    }

    #[test]
    fn list_rules_result_json_contains_required_keys() {
        let result = ListRulesResult {
            rules: vec![],
            active_count: 0,
            scanned_id_range: ScannedIdRange { start: 0, end: 0 },
            rules_skipped: 0,
            gaps_seen: 0,
            audit_log_missing: vec![],
        };
        let json = serde_json::to_string(&result).expect("serialise");
        for key in &[
            "rules",
            "active_count",
            "scanned_id_range",
            "rules_skipped",
            "gaps_seen",
            "audit_log_missing",
        ] {
            assert!(
                json.contains(&format!("\"{key}\"")),
                "JSON must contain '{key}' key; got: {json}"
            );
        }
    }

    #[test]
    fn list_rules_entry_valid_until_absent_when_none() {
        let entry = ListRulesEntry {
            rule_id: 0,
            name: "r".to_owned(),
            context_type_label: "default".to_owned(),
            signer_count: 1,
            policy_count: 0,
            valid_until: None,
        };
        let json = serde_json::to_string(&entry).expect("serialise");
        assert!(
            !json.contains("valid_until"),
            "valid_until must be absent when None; got: {json}"
        );
    }

    #[test]
    fn list_rules_entry_valid_until_present_when_some() {
        let entry = ListRulesEntry {
            rule_id: 0,
            name: "r".to_owned(),
            context_type_label: "default".to_owned(),
            signer_count: 1,
            policy_count: 0,
            valid_until: Some(999_999),
        };
        let json = serde_json::to_string(&entry).expect("serialise");
        assert!(
            json.contains("\"valid_until\":999999"),
            "valid_until must be present when Some; got: {json}"
        );
    }

    #[test]
    fn scanned_id_range_json_shape() {
        let range = ScannedIdRange { start: 0, end: 4 };
        let json = serde_json::to_string(&range).expect("serialise");
        assert!(json.contains("\"start\":0"), "start must be 0; got: {json}");
        assert!(json.contains("\"end\":4"), "end must be 4; got: {json}");
    }
}
