//! Offline emission tests for the DeFi adapter value-action audit row.
//!
//! These run in push CI (no testnet gate). They drive
//! [`DefiAdapterCtx::emit_value_action_submitted`] against a temp-file-backed
//! [`AuditWriter`] and read the JSONL back, asserting the `value_action_submitted`
//! row shape and the all-fields-required emission guard. The row's legs are the
//! SAME `ValueLegRecord`s the policy gate sizes (produced here through
//! `derive_value_class`, exactly as the dispatch path does), so a regression in
//! the emission plumbing — a broken guard, a dropped write, a wrong row kind —
//! fails here rather than only in the testnet acceptance run (which push CI
//! skips). The on-chain call-site wiring is covered additionally by the DeFi
//! testnet acceptance tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only"
)]

use std::io::BufRead as _;
use std::sync::{Arc, Mutex};

use serde_json::json;
use stellar_agent_core::audit_log::{AuditWriter, ValueLegRecord};
use stellar_agent_core::policy::v1::ValueClass;
use stellar_agent_core::policy::v1::value::derive_value_class;
use stellar_agent_defi::adapter::DefiAdapterCtx;
use stellar_agent_defi::pins::DefiContractPin;
use stellar_agent_network::StellarRpcClient;
use tempfile::TempDir;

const CHAIN_ID: &str = "stellar:testnet";
const DEST_G: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
const CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

/// Opens a temp-file `AuditWriter` wrapped for the adapter's `audit_writer`
/// field and returns it with the owning `TempDir` (kept alive by the caller).
fn tmp_writer() -> (Arc<Mutex<AuditWriter>>, TempDir) {
    let dir = tempfile::tempdir().expect("tmp dir");
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(path, None).expect("AuditWriter::open");
    (Arc::new(Mutex::new(writer)), dir)
}

/// Reads all JSONL rows from the temp file and parses each as a JSON value.
fn read_rows(dir: &TempDir) -> Vec<serde_json::Value> {
    let path = dir.path().join("audit.jsonl");
    let file = std::fs::File::open(&path).expect("audit.jsonl exists");
    std::io::BufReader::new(file)
        .lines()
        .map(|l| serde_json::from_str(&l.expect("line")).expect("valid JSON row"))
        .collect()
}

/// The SAME legs the policy gate sizes for a payment, produced through the
/// canonical `derive_value_class` (single-derivation invariant).
fn payment_legs() -> Vec<ValueLegRecord> {
    let args = json!({
        "amount": "1000000",
        "asset": "native",
        "destination": DEST_G,
    });
    let ValueClass::Value(effects) = derive_value_class("stellar_pay", &args) else {
        panic!("stellar_pay must derive a value-moving descriptor");
    };
    effects.legs().iter().map(Into::into).collect()
}

fn testnet_pin() -> DefiContractPin {
    DefiContractPin::new(
        "blend", "v2", "default", CHAIN_ID, CONTRACT, [0u8; 32], "895845f",
    )
}

#[test]
fn emit_value_action_submitted_writes_a_value_action_row() {
    let (writer, dir) = tmp_writer();
    let legs = payment_legs();
    let pin = testnet_pin();
    let rpc = StellarRpcClient::new("https://soroban-testnet.stellar.org").expect("valid URL");

    let mut ctx = DefiAdapterCtx::new("default", &pin, &rpc);
    ctx.audit_writer = Some(Arc::clone(&writer));
    ctx.audit_legs = Some(&legs);
    ctx.audit_tool = Some("stellar_blend_lend");
    ctx.chain_id = Some(CHAIN_ID);

    ctx.emit_value_action_submitted("abcd1234…wxyz5678", 42, "req-defi-1");

    let rows = read_rows(&dir);
    assert_eq!(rows.len(), 1, "exactly one row must be written");
    let row = &rows[0];
    assert_eq!(row["kind"], "value_action_submitted", "row kind");
    assert_eq!(row["tool"], "stellar_blend_lend", "outer tool identity");
    assert_eq!(row["chain_id"], CHAIN_ID, "chain id");
    assert_eq!(row["ledger"], 42, "confirmed ledger");
    assert_eq!(row["policy_decision"], "allow", "allow-path decision");
    assert_eq!(
        row["legs"].as_array().expect("legs array").len(),
        legs.len(),
        "the row records exactly the gate-sized legs"
    );
    // The redacted hash is recorded verbatim; no full 64-hex hash leaks.
    assert_eq!(
        row["transaction_hash_redacted"], "abcd1234…wxyz5678",
        "redacted tx hash"
    );
}

#[test]
fn emit_value_action_submitted_skips_when_audit_tool_absent() {
    // The all-fields-required guard: with `audit_tool = None` the adapter emits
    // NOTHING (a value row without its tool identity must never be written).
    let (writer, dir) = tmp_writer();
    let legs = payment_legs();
    let pin = testnet_pin();
    let rpc = StellarRpcClient::new("https://soroban-testnet.stellar.org").expect("valid URL");

    let mut ctx = DefiAdapterCtx::new("default", &pin, &rpc);
    ctx.audit_writer = Some(Arc::clone(&writer));
    ctx.audit_legs = Some(&legs);
    ctx.audit_tool = None;
    ctx.chain_id = Some(CHAIN_ID);

    ctx.emit_value_action_submitted("abcd1234…wxyz5678", 42, "req-defi-2");

    // The file may not exist (no write ever opened it) or be empty; either way
    // there must be zero rows.
    let path = dir.path().join("audit.jsonl");
    let rows = if path.exists() {
        read_rows(&dir)
    } else {
        Vec::new()
    };
    assert!(
        rows.is_empty(),
        "no row may be written without the tool identity"
    );
}
