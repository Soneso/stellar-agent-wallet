//! The signers manager a test hands to `PinCheck` or `MulticallSubmitArgs`
//! for the pinned-hash drift check, on its own audit log.
//!
//! Included by path (`#[path = "common/pin_check_manager.rs"]`) from the
//! testnet suites and the offline mocks alike, so it carries no feature gate.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_smart_account::managers::signers::{SignersManager, SignersManagerConfig};

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const CHAIN_ID: &str = "stellar:testnet";
const TIMEOUT: Duration = Duration::from_secs(120);

/// Builds a testnet signers manager over `primary_rpc_url` /
/// `secondary_rpc_url` whose audit log is `pin-check-audit.jsonl` under
/// `dir`, labelled `profile`.
///
/// The log starts empty, so the drift check fetches each authorizing rule
/// other than 0 and passes it: the suites that use this helper install their
/// rules through managers that write no pin record here.
///
/// # Panics
///
/// Panics when the audit writer cannot open or the manager rejects its
/// configuration.
pub fn pin_check_manager(
    primary_rpc_url: &str,
    secondary_rpc_url: &str,
    profile: &str,
    dir: &Path,
) -> SignersManager {
    let audit_log_path = dir.join("pin-check-audit.jsonl");
    let writer = AuditWriter::open(audit_log_path.clone(), None)
        .unwrap_or_else(|e| panic!("temporary audit writer must open: {e}"));
    SignersManager::new(SignersManagerConfig::new(
        primary_rpc_url.to_owned(),
        secondary_rpc_url.to_owned(),
        Arc::new(Mutex::new(writer)),
        audit_log_path,
        TESTNET_PASSPHRASE.to_owned(),
        profile.to_owned(),
        TIMEOUT,
        CHAIN_ID.to_owned(),
    ))
    .unwrap_or_else(|e| panic!("SignersManager construction must succeed: {e}"))
}
