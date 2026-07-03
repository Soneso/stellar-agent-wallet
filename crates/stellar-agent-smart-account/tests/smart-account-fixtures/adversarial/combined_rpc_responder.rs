//! `CombinedRpcResponder` — a `wiremock::Respond` implementation shared across
//! adversarial fixtures that require both `getLedgerEntries` and `simulateTransaction` mocking.
//!
//! Routes by JSON-RPC `method`:
//! - `getLedgerEntries`: dispatches to account entry or contract-instance entry based
//!   on the XDR-decoded key type in the request body.
//! - `simulateTransaction`: dispatches in call-sequence order to a list of canned responses.
//!
//! Also provides [`TracedSequencedSimulate`] and [`TracedCombinedRpcResponder`] for
//! tests that need in-critical-section ordering evidence: each simulate call records a
//! `(caller_id, global_tick)` entry into a shared trace, so the caller can assert that
//! the simulate sequences of two concurrent callers do not interleave.
//!
//! # Purpose
//!
//! Shared test infrastructure for the atomic signer-threshold-update adversarial fixtures.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use stellar_xdr::{LedgerKey, Limits, ReadXdr, ScAddress};
use wiremock::{Request, Respond, ResponseTemplate};

use super::rpc_mock_helpers::{
    build_ledger_entries_account, build_ledger_entries_contract_instance,
    build_ledger_entries_two_contract_instances,
};

/// A canned JSON-RPC result responder for fixtures that only need one result.
#[allow(
    dead_code,
    reason = "not all adversarial fixtures need the simple responder"
)]
pub struct JsonRpcResultResponder(pub serde_json::Value);

impl Respond for JsonRpcResultResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).unwrap_or(serde_json::json!({}));
        let req_id = body.get("id").cloned().unwrap_or(serde_json::json!(1));
        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": self.0
            }))
            .insert_header("content-type", "application/json")
    }
}

// ── SequencedSimulate ─────────────────────────────────────────────────────────

/// A sequence of `simulateTransaction` canned responses, indexed by call count.
///
/// If the call count exceeds the number of responses, the last response is reused.
pub struct SequencedSimulate {
    responses: Vec<serde_json::Value>,
    call: AtomicUsize,
}

impl SequencedSimulate {
    #[allow(
        dead_code,
        reason = "not all adversarial fixtures need simulate sequencing"
    )]
    pub fn new(responses: Vec<serde_json::Value>) -> Self {
        assert!(
            !responses.is_empty(),
            "at least one simulate response required"
        );
        Self {
            responses,
            call: AtomicUsize::new(0),
        }
    }

    #[allow(
        dead_code,
        reason = "not all adversarial fixtures need simulate sequencing"
    )]
    pub fn next(&self) -> serde_json::Value {
        let idx = self
            .call
            .fetch_add(1, Ordering::Relaxed)
            .min(self.responses.len().saturating_sub(1));
        self.responses[idx].clone()
    }
}

// ── LedgerEntriesConfig ───────────────────────────────────────────────────────

/// Configuration for key-dispatched `getLedgerEntries` responses.
///
/// Account-key requests return the account entry for `source_g`.
/// ContractData-key requests return the contract-instance entry (or entries).
#[allow(dead_code, reason = "not all adversarial fixtures use ledger dispatch")]
pub enum LedgerEntriesConfig {
    /// One policy: serves a single contract-instance entry with `wasm_hash`.
    #[allow(
        dead_code,
        reason = "used only by the fixtures that need a single policy"
    )]
    SinglePolicy {
        source_g: String,
        policy_addr: ScAddress,
        wasm_hash: [u8; 32],
    },
    /// Two policies (multi-match test): serves two contract-instance entries.
    #[allow(dead_code, reason = "used only by the fixtures that need two policies")]
    TwoPolicies {
        source_g: String,
        policy_addr_a: ScAddress,
        wasm_hash_a: [u8; 32],
        policy_addr_b: ScAddress,
        wasm_hash_b: [u8; 32],
    },
    /// No policies: returns empty entries for any contract-data key.
    #[allow(dead_code, reason = "used only by the fixtures that need no policies")]
    NoPolicies { source_g: String },
    /// Empty contract instance (no wasm hash): policy exists but hash is unknown.
    #[allow(
        dead_code,
        reason = "used only by the fixtures that need unknown hashes"
    )]
    UnknownHash {
        source_g: String,
        policy_addr: ScAddress,
        wasm_hash: [u8; 32],
    },
}

impl LedgerEntriesConfig {
    #[allow(dead_code, reason = "not all adversarial fixtures use ledger dispatch")]
    pub fn respond(&self, key_b64: &str) -> serde_json::Value {
        match self {
            LedgerEntriesConfig::SinglePolicy {
                source_g,
                policy_addr,
                wasm_hash,
            } => {
                if is_contract_data_key(key_b64) {
                    build_ledger_entries_contract_instance(policy_addr, *wasm_hash)
                } else {
                    build_ledger_entries_account(source_g)
                }
            }
            LedgerEntriesConfig::TwoPolicies {
                source_g,
                policy_addr_a,
                wasm_hash_a,
                policy_addr_b,
                wasm_hash_b,
            } => {
                if is_contract_data_key(key_b64) {
                    build_ledger_entries_two_contract_instances(
                        policy_addr_a,
                        *wasm_hash_a,
                        policy_addr_b,
                        *wasm_hash_b,
                    )
                } else {
                    build_ledger_entries_account(source_g)
                }
            }
            LedgerEntriesConfig::NoPolicies { source_g } => {
                if is_contract_data_key(key_b64) {
                    serde_json::json!({ "entries": [], "latestLedger": 1000 })
                } else {
                    build_ledger_entries_account(source_g)
                }
            }
            LedgerEntriesConfig::UnknownHash {
                source_g,
                policy_addr,
                wasm_hash,
            } => {
                if is_contract_data_key(key_b64) {
                    build_ledger_entries_contract_instance(policy_addr, *wasm_hash)
                } else {
                    build_ledger_entries_account(source_g)
                }
            }
        }
    }
}

// ── CombinedRpcResponder ──────────────────────────────────────────────────────

/// A `wiremock::Respond` that dispatches by JSON-RPC method:
/// - `getLedgerEntries` → `LedgerEntriesConfig`
/// - `simulateTransaction` → `SequencedSimulate`
#[allow(
    dead_code,
    reason = "not all adversarial fixtures need combined RPC dispatch"
)]
pub struct CombinedRpcResponder {
    ledger_entries: LedgerEntriesConfig,
    simulate: SequencedSimulate,
}

impl CombinedRpcResponder {
    /// Constructs a responder with a single policy contract.
    #[allow(
        dead_code,
        reason = "not all adversarial fixtures need combined RPC dispatch"
    )]
    pub fn new(
        source_g: &str,
        policy_addr: &ScAddress,
        wasm_hash: [u8; 32],
        simulate: SequencedSimulate,
    ) -> Self {
        Self {
            ledger_entries: LedgerEntriesConfig::SinglePolicy {
                source_g: source_g.to_owned(),
                policy_addr: policy_addr.clone(),
                wasm_hash,
            },
            simulate,
        }
    }

    /// Constructs a responder with two policy contracts.
    #[allow(
        dead_code,
        reason = "not all adversarial fixtures need combined RPC dispatch"
    )]
    pub fn new_two_policies(
        source_g: &str,
        policy_addr_a: &ScAddress,
        wasm_hash_a: [u8; 32],
        policy_addr_b: &ScAddress,
        wasm_hash_b: [u8; 32],
        simulate: SequencedSimulate,
    ) -> Self {
        Self {
            ledger_entries: LedgerEntriesConfig::TwoPolicies {
                source_g: source_g.to_owned(),
                policy_addr_a: policy_addr_a.clone(),
                wasm_hash_a,
                policy_addr_b: policy_addr_b.clone(),
                wasm_hash_b,
            },
            simulate,
        }
    }

    /// Constructs a responder with no policies (empty contract-data entries).
    #[allow(
        dead_code,
        reason = "not all adversarial fixtures need combined RPC dispatch"
    )]
    pub fn new_no_policies(source_g: &str, simulate: SequencedSimulate) -> Self {
        Self {
            ledger_entries: LedgerEntriesConfig::NoPolicies {
                source_g: source_g.to_owned(),
            },
            simulate,
        }
    }

    /// Constructs a responder with one policy that has an unknown wasm hash.
    #[allow(
        dead_code,
        reason = "not all adversarial fixtures need combined RPC dispatch"
    )]
    pub fn new_unknown_hash(
        source_g: &str,
        policy_addr: &ScAddress,
        unknown_wasm_hash: [u8; 32],
        simulate: SequencedSimulate,
    ) -> Self {
        Self {
            ledger_entries: LedgerEntriesConfig::UnknownHash {
                source_g: source_g.to_owned(),
                policy_addr: policy_addr.clone(),
                wasm_hash: unknown_wasm_hash,
            },
            simulate,
        }
    }
}

impl Respond for CombinedRpcResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).unwrap_or(serde_json::json!({}));
        let req_id = body.get("id").cloned().unwrap_or(serde_json::json!(1));
        let method_name = body
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let result = match method_name {
            "getLedgerEntries" => {
                let first_key = extract_first_ledger_key(&body);
                self.ledger_entries
                    .respond(first_key.as_deref().unwrap_or(""))
            }
            "simulateTransaction" => self.simulate.next(),
            _ => serde_json::json!({}),
        };

        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result
            }))
            .insert_header("content-type", "application/json")
    }
}

// ── TracedSequencedSimulate ───────────────────────────────────────────────────

/// A [`SequencedSimulate`] variant that records in-critical-section ordering evidence.
///
/// Each `next()` call atomically increments a shared global tick and appends
/// `(caller_id, tick)` to a shared trace.  Two concurrent callers given separate
/// `TracedSequencedSimulate` instances (with the same `global_tick` and `trace`)
/// produce a trace whose entries can be inspected to verify non-interleaving:
/// if the per-rule mutex serialises the callers correctly, all entries for
/// `caller_id = A` will have ticks strictly less than (or greater than) all
/// entries for `caller_id = B`.
#[allow(dead_code, reason = "used only by the concurrent_signing_race fixture")]
pub struct TracedSequencedSimulate {
    responses: Vec<serde_json::Value>,
    call: AtomicUsize,
    /// Global tick counter shared across all traced instances in one test invocation.
    global_tick: Arc<AtomicU64>,
    /// Identifies which caller this instance belongs to.
    caller_id: u8,
    /// Shared trace: `(caller_id, global_tick)` per simulate call.
    trace: Arc<Mutex<Vec<(u8, u64)>>>,
}

impl TracedSequencedSimulate {
    /// Creates a new traced simulate sequencer.
    ///
    /// - `responses` — canned simulate responses in call order.
    /// - `global_tick` — shared atomic tick counter (shared across both callers' instances).
    /// - `caller_id` — opaque identifier for this caller (e.g. 1 or 2).
    /// - `trace` — shared append-only log of `(caller_id, tick)` entries.
    #[allow(dead_code, reason = "used only by the concurrent_signing_race fixture")]
    pub fn new(
        responses: Vec<serde_json::Value>,
        global_tick: Arc<AtomicU64>,
        caller_id: u8,
        trace: Arc<Mutex<Vec<(u8, u64)>>>,
    ) -> Self {
        assert!(
            !responses.is_empty(),
            "at least one simulate response required"
        );
        Self {
            responses,
            call: AtomicUsize::new(0),
            global_tick,
            caller_id,
            trace,
        }
    }

    /// Returns the next canned response and records a trace entry.
    #[allow(dead_code, reason = "called via TracedCombinedRpcResponder::respond")]
    #[allow(
        clippy::expect_used,
        reason = "test-only mock; mutex poison is unrecoverable in this context"
    )]
    pub fn next(&self) -> serde_json::Value {
        // Record ordering evidence BEFORE indexing into responses so that the tick
        // reflects when the mock entered the simulate handler — i.e., inside the
        // production code's critical section where the RPC call is made.
        let tick = self.global_tick.fetch_add(1, Ordering::SeqCst);
        self.trace
            .lock()
            .expect("trace mutex must not be poisoned")
            .push((self.caller_id, tick));

        let idx = self
            .call
            .fetch_add(1, Ordering::Relaxed)
            .min(self.responses.len().saturating_sub(1));
        self.responses[idx].clone()
    }

    /// Returns a clone of the shared trace for post-test inspection.
    #[allow(dead_code, reason = "used only by the concurrent_signing_race fixture")]
    pub fn trace(&self) -> Arc<Mutex<Vec<(u8, u64)>>> {
        Arc::clone(&self.trace)
    }
}

// ── TracedCombinedRpcResponder ────────────────────────────────────────────────

/// A `wiremock::Respond` that dispatches by JSON-RPC method, using a
/// [`TracedSequencedSimulate`] for in-critical-section ordering evidence.
///
/// Used by the `concurrent_signing_race` fixture to verify that two concurrent
/// callers do not interleave inside the per-rule async mutex.
#[allow(dead_code, reason = "used only by the concurrent_signing_race fixture")]
pub struct TracedCombinedRpcResponder {
    ledger_entries: LedgerEntriesConfig,
    simulate: TracedSequencedSimulate,
}

impl TracedCombinedRpcResponder {
    /// Constructs a traced responder with a single policy contract.
    #[allow(dead_code, reason = "used only by the concurrent_signing_race fixture")]
    pub fn new(
        source_g: &str,
        policy_addr: &ScAddress,
        wasm_hash: [u8; 32],
        simulate: TracedSequencedSimulate,
    ) -> Self {
        Self {
            ledger_entries: LedgerEntriesConfig::SinglePolicy {
                source_g: source_g.to_owned(),
                policy_addr: policy_addr.clone(),
                wasm_hash,
            },
            simulate,
        }
    }

    /// Returns a clone of the shared trace for post-test inspection.
    #[allow(dead_code, reason = "used only by the concurrent_signing_race fixture")]
    pub fn trace(&self) -> Arc<Mutex<Vec<(u8, u64)>>> {
        self.simulate.trace()
    }
}

impl Respond for TracedCombinedRpcResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).unwrap_or(serde_json::json!({}));
        let req_id = body.get("id").cloned().unwrap_or(serde_json::json!(1));
        let method_name = body
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let result = match method_name {
            "getLedgerEntries" => {
                let first_key = extract_first_ledger_key(&body);
                self.ledger_entries
                    .respond(first_key.as_deref().unwrap_or(""))
            }
            "simulateTransaction" => self.simulate.next(),
            _ => serde_json::json!({}),
        };

        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result
            }))
            .insert_header("content-type", "application/json")
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extracts the first key from a `getLedgerEntries` JSON-RPC request body.
#[allow(dead_code, reason = "not all adversarial fixtures use ledger dispatch")]
fn extract_first_ledger_key(body: &serde_json::Value) -> Option<String> {
    body.get("params")
        .and_then(|p| p.get("keys"))
        .and_then(|k| k.as_array())
        .and_then(|arr| arr.first())
        .and_then(|k| k.as_str())
        .map(|s| s.to_owned())
}

/// Returns `true` if the XDR-base64 key decodes as `LedgerKey::ContractData`.
#[allow(dead_code, reason = "not all adversarial fixtures use ledger dispatch")]
fn is_contract_data_key(key_b64: &str) -> bool {
    LedgerKey::from_xdr_base64(key_b64, Limits::none())
        .map(|k| matches!(k, LedgerKey::ContractData(_)))
        .unwrap_or(false)
}
