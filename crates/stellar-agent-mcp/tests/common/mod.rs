pub mod policy_mock;
pub mod v1_engine_mock;

use std::sync::{Arc, Mutex, OnceLock};

use rmcp::model::CallToolResult;
use stellar_agent_test_support::signed_envelope::{TESTNET_PASSPHRASE, get_network_result};

/// Passphrase of a third Stellar network — neither testnet nor mainnet.
///
/// An endpoint reporting it under a testnet profile is the plain
/// wrong-endpoint case: the mismatch refusal fires, and the mainnet guard
/// (which has a refusal of its own) does not.
#[allow(
    dead_code,
    reason = "shared across integration-test binaries; unused in some"
)]
pub const FUTURENET_PASSPHRASE: &str = "Test SDF Future Network ; October 2022";

/// The network passphrase a mocked RPC endpoint reports from `getNetwork`.
///
/// Every commit tool probes endpoint identity on the client it will submit
/// with, so any mock serving a commit path has to answer `getNetwork`. The
/// passphrase sits behind a lock so one running mock server can report two
/// different identities across two calls, which is how a test observes the
/// state a refused commit left behind.
#[derive(Clone)]
#[allow(
    dead_code,
    reason = "shared across integration-test binaries; unused in some"
)]
pub struct EndpointNetwork(Arc<Mutex<String>>);

#[allow(
    dead_code,
    reason = "shared across integration-test binaries; unused in some"
)]
impl EndpointNetwork {
    /// Reports the canonical testnet passphrase.
    #[must_use]
    pub fn testnet() -> Self {
        Self::reporting(TESTNET_PASSPHRASE)
    }

    /// Reports `passphrase`.
    #[must_use]
    pub fn reporting(passphrase: &str) -> Self {
        Self(Arc::new(Mutex::new(passphrase.to_owned())))
    }

    /// Changes the passphrase every subsequent `getNetwork` answers with.
    pub fn set(&self, passphrase: &str) {
        *self.0.lock().expect("endpoint network lock") = passphrase.to_owned();
    }

    /// The `getNetwork` JSON-RPC result body for the current passphrase.
    #[must_use]
    pub fn result(&self) -> serde_json::Value {
        get_network_result(&self.0.lock().expect("endpoint network lock"))
    }
}

/// Fixed non-secret 32-byte value used as the audit chain-root HMAC key by
/// every test in a binary that calls [`install_test_audit_key`].
///
/// MUST be identical across every call within one test binary — see that
/// function's doc comment for why a per-call random key (the naive seeding
/// choice) breaks `AuditWriterRegistry`'s process-lifetime cache.
const TEST_AUDIT_KEY_BYTES: [u8; 32] = [0x37_u8; 32];

/// Per-process temp directory backing every `install_test_audit_key` call in
/// a test binary — created once, reused by every test. As a `static`, this
/// value is never dropped at process exit (Rust does not run destructors on
/// statics), so the directory is NOT deleted by this binding; it is left for
/// the OS temp-directory cleanup policy, same as any other leaked tempdir.
static TEST_AUDIT_LOG_DIR: OnceLock<tempfile::TempDir> = OnceLock::new();

/// Redirects `profile.audit_log_path` to a per-process temp directory and
/// seeds a fixed 32-byte audit chain-root HMAC key at the profile's
/// `audit_log_hash_chain_key_id` keyring coordinate, under the process-global
/// mock keyring store (`stellar_agent_test_support::keyring_mock::install`
/// must already be installed by the caller).
///
/// Every full commit/submit round-trip test needs this: `require_value_audit_writer`
/// refuses BEFORE the signer is loaded or the transaction is submitted unless
/// the profile's audit chain-root key is acquirable — mirrors
/// `install_test_nonce_key`'s per-test seeding pattern for the nonce mint's
/// HMAC key.
///
/// # Why a FIXED path and a FIXED key, not a fresh tempdir/random key per test
///
/// `AuditWriterRegistry` is a process-global cache keyed by profile name
/// (`stellar-agent-core::audit_log::writer`): the FIRST call for a given
/// profile name in this test binary's process pins the `(log_path, hmac_key)`
/// pair for every later call with that same profile name — a later call
/// presenting a different path or key fails closed
/// (`WriterError::PathMismatch` / `HmacKeyMismatch`), which this crate's
/// `require_value_audit_writer` maps to the SAME `audit.chain_key_unavailable`
/// refusal as a genuinely-missing key. Since every test built on
/// `testnet_profile_with_rpc`-style helpers shares the same signer account
/// (hence the same profile name), every test in one binary that reaches the
/// audit pre-flight MUST present the identical path and key regardless of
/// which test happens to run first under `#[serial]` — a per-test tempdir or
/// random key reproduces the exact registry collision this function exists to
/// avoid. Redirecting to a temp directory (rather than the real
/// `canonical_data_root()` default, which `default_audit_log_path_for` does
/// NOT gate behind `STELLAR_AGENT_HOME`) also keeps these tests from writing a
/// real file under the developer's or CI runner's actual home directory.
#[allow(
    dead_code,
    reason = "shared across integration-test binaries; unused in some"
)]
pub fn install_test_audit_key(profile: &mut stellar_agent_core::profile::schema::Profile) {
    use base64::Engine as _;

    let dir =
        TEST_AUDIT_LOG_DIR.get_or_init(|| tempfile::tempdir().expect("tempdir for audit log"));
    profile.audit_log_path = dir
        .path()
        .join(format!("{}.jsonl", profile.mcp_signer_default.account));

    let key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(TEST_AUDIT_KEY_BYTES);
    let coord = &profile.audit_log_hash_chain_key_id;
    keyring_core::Entry::new(&coord.service, &coord.account)
        .expect("Entry::new for audit key")
        .set_password(&key_b64)
        .expect("set_password for audit key");
}

/// Asserts the shared business-error envelope invariants on a tool result and
/// returns `(code, message, full_text)` for further per-test assertions.
///
/// The normalised business-error wire contract is:
///
/// ```json
/// { "ok": false, "error": { "code": "...", "message": "..." }, "request_id": "..." }
/// ```
///
/// This checks `is_error == Some(true)`, `ok == false`, and a non-empty
/// `request_id`, then extracts `error.code` and `error.message`.
///
/// `request_id` is freshly minted per call and therefore intentionally excluded
/// from the returned tuple: indistinguishability comparisons across two refusals
/// must compare `(code, message)`, never the full JSON.
#[must_use]
#[allow(
    dead_code,
    reason = "shared across integration-test binaries; unused in some"
)]
pub fn assert_business_envelope(result: &CallToolResult) -> (String, String, String) {
    assert_eq!(
        result.is_error,
        Some(true),
        "business-error result must set is_error = true"
    );
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("business-error result must carry a text content block");
    let value: serde_json::Value =
        serde_json::from_str(&text).expect("business-error content must be JSON");
    assert_eq!(
        value["ok"],
        serde_json::json!(false),
        "business-error envelope must have ok:false: {value}"
    );
    assert!(
        value["request_id"].as_str().is_some_and(|s| !s.is_empty()),
        "business-error envelope must carry a non-empty request_id: {value}"
    );
    let code = value["error"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let message = value["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    (code, message, text)
}

// ─────────────────────────────────────────────────────────────────────────────
// Endpoint hash echo
// ─────────────────────────────────────────────────────────────────────────────

/// The transaction hash a real endpoint reports for the `sendTransaction`
/// request it was handed.
///
/// Computed from the envelope in the request, under the testnet passphrase the
/// mocked endpoint serves, so the mock answers what a real one would. The
/// wallet computes the same hash from the bytes it signed and reports a
/// disagreement as `submission.hash_mismatch`; a mock returning a canned value
/// would trip that on every call.
///
/// # Panics
///
/// Panics if the request is not a `sendTransaction` carrying a decodable
/// envelope.
#[must_use]
#[allow(
    dead_code,
    reason = "shared across integration-test binaries; unused in some"
)]
pub fn submitted_tx_hash(request: &wiremock::Request) -> String {
    let body = serde_json::from_slice::<serde_json::Value>(&request.body)
        .expect("sendTransaction request body must be JSON");
    stellar_agent_test_support::send_transaction_hash_hex(&body, TESTNET_PASSPHRASE)
}

/// The transaction hash a real endpoint reports for the `getTransaction`
/// request it was handed: the one the caller asked about.
///
/// # Panics
///
/// Panics if the request is not a `getTransaction` carrying a `hash`
/// parameter.
#[must_use]
#[allow(
    dead_code,
    reason = "shared across integration-test binaries; unused in some"
)]
pub fn polled_tx_hash(request: &wiremock::Request) -> String {
    let body = serde_json::from_slice::<serde_json::Value>(&request.body)
        .expect("getTransaction request body must be JSON");
    body.get("params")
        .and_then(|p| p.get("hash"))
        .and_then(serde_json::Value::as_str)
        .expect("getTransaction request must carry a `params.hash` string")
        .to_owned()
}

// ─────────────────────────────────────────────────────────────────────────────
// Data-root isolation
// ─────────────────────────────────────────────────────────────────────────────

/// A temporary directory installed as the wallet's data root for the lifetime
/// of the guard.
///
/// The submission receipt store, the spending-window file and the
/// pending-approval store all resolve under the canonical data root. Without
/// this, an integration test writes to the operator's real directory and
/// inherits what previous runs and sibling tests left there: the duplicate
/// check refuses a fresh submission whose `(source, sequence)` a leftover
/// receipt already holds. Every test that commits holds one of these, and
/// `#[serial]` is what makes the process-wide override safe.
pub struct IsolatedDataRoot {
    _dir: tempfile::TempDir,
    _guard: stellar_agent_test_support::StellarAgentHomeGuard,
}

/// Installs a fresh data root for the lifetime of the returned guard.
///
/// # Panics
///
/// Panics if the temporary directory cannot be created.
#[must_use]
#[allow(
    dead_code,
    reason = "shared across integration-test binaries; unused in some"
)]
pub fn isolated_data_root() -> IsolatedDataRoot {
    let dir = tempfile::tempdir().expect("temporary data root");
    let guard = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
    IsolatedDataRoot {
        _dir: dir,
        _guard: guard,
    }
}

/// Returns the `details` object a business-error envelope carries, or `None`.
///
/// Two refusals that must be indistinguishable have to agree here as well as
/// on the code and the message: a `details` object present on one and absent
/// on the other tells the caller which refusal it got.
#[must_use]
#[allow(
    dead_code,
    reason = "shared across integration-test binaries; unused in some"
)]
pub fn business_envelope_details(result: &CallToolResult) -> Option<serde_json::Value> {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("business-error result must carry a text content block");
    let value: serde_json::Value =
        serde_json::from_str(&text).expect("business-error content must be JSON");
    value.get("error").and_then(|e| e.get("details")).cloned()
}

// ─────────────────────────────────────────────────────────────────────────────
// Timeout harness
// ─────────────────────────────────────────────────────────────────────────────

/// A mocked endpoint that accepts every send and never confirms it.
///
/// This is the shape the durable record exists for: the transaction was taken
/// for inclusion and the confirmation poll runs out of time, so the wallet
/// cannot say whether it applied.
#[allow(
    dead_code,
    reason = "shared across integration-test binaries; unused in some"
)]
pub struct TimeoutRpc {
    /// `(ledger key XDR, account entry XDR)` per answerable account.
    accounts: Vec<(String, String)>,
    /// Simulation result body for `simulateTransaction`, when the flow needs
    /// one.
    simulate: Option<serde_json::Value>,
    /// When set, `getTransaction` confirms the submission instead of never
    /// answering for it.
    confirm_in_ledger: Option<u32>,
}

#[allow(
    dead_code,
    reason = "shared across integration-test binaries; unused in some"
)]
impl TimeoutRpc {
    /// Answers `getLedgerEntries` for `accounts` and never confirms a send.
    #[must_use]
    pub fn new(accounts: Vec<(String, String)>) -> Self {
        Self {
            accounts,
            simulate: None,
            confirm_in_ledger: None,
        }
    }

    /// Confirms every submission in `ledger` instead of never answering for
    /// it.
    #[must_use]
    pub fn confirming_in(mut self, ledger: u32) -> Self {
        self.confirm_in_ledger = Some(ledger);
        self
    }

    /// Adds a `simulateTransaction` answer.
    #[must_use]
    pub fn with_simulate(mut self, simulate: serde_json::Value) -> Self {
        self.simulate = Some(simulate);
        self
    }
}

impl wiremock::Respond for TimeoutRpc {
    fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
        let body = serde_json::from_slice::<serde_json::Value>(&request.body)
            .unwrap_or_else(|_| serde_json::json!({}));
        let req_id = body
            .get("id")
            .cloned()
            .unwrap_or_else(|| serde_json::json!(1));
        let rpc_method = body
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let result = match rpc_method {
            "getNetwork" => EndpointNetwork::testnet().result(),
            "getFeeStats" => serde_json::json!({
                "sorobanInclusionFee": {
                    "max": "100", "min": "100", "mode": "100", "p10": "100", "p20": "100",
                    "p30": "100", "p40": "100", "p50": "100", "p60": "100", "p70": "100",
                    "p80": "100", "p90": "100", "p95": "100", "p99": "100",
                    "transactionCount": "10", "ledgerCount": 5
                },
                "inclusionFee": {
                    "max": "100", "min": "100", "mode": "100", "p10": "100", "p20": "100",
                    "p30": "100", "p40": "100", "p50": "100", "p60": "100", "p70": "100",
                    "p80": "100", "p90": "100", "p95": "100", "p99": "100",
                    "transactionCount": "10", "ledgerCount": 5
                },
                "latestLedger": 1001
            }),
            "getLedgerEntries" => {
                let raw = String::from_utf8_lossy(&request.body);
                let entries: Vec<serde_json::Value> = self
                    .accounts
                    .iter()
                    .filter(|(key, _)| raw.contains(key.as_str()))
                    .map(|(key, entry)| {
                        serde_json::json!({
                            "key": key,
                            "xdr": entry,
                            "lastModifiedLedgerSeq": 1000
                        })
                    })
                    .collect();
                serde_json::json!({ "entries": entries, "latestLedger": 1001 })
            }
            "simulateTransaction" => self
                .simulate
                .clone()
                .unwrap_or_else(|| serde_json::json!({})),
            "sendTransaction" => serde_json::json!({
                "hash": submitted_tx_hash(request),
                "status": "PENDING",
                "latestLedger": 1001,
                "latestLedgerCloseTime": "1234567890"
            }),
            "getTransaction" => match self.confirm_in_ledger {
                Some(ledger) => serde_json::json!({
                    "status": "SUCCESS",
                    "latestLedger": 1002,
                    "oldestLedger": 1,
                    "ledger": ledger,
                }),
                None => serde_json::json!({
                    "status": "NOT_FOUND",
                    "latestLedger": 1002,
                    "oldestLedger": 1,
                }),
            },
            _ => serde_json::json!({}),
        };

        wiremock::ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result,
            }))
            .insert_header("content-type", "application/json")
    }
}

/// A profile whose submissions time out after one second, under its own signer
/// account so its audit log is not shared with another test in this binary.
///
/// # Panics
///
/// Panics if the test audit key cannot be installed.
#[must_use]
#[allow(
    dead_code,
    reason = "shared across integration-test binaries; unused in some"
)]
pub fn timeout_profile(
    rpc_url: &str,
    account: &str,
) -> stellar_agent_core::profile::schema::Profile {
    let mut p = stellar_agent_core::profile::schema::Profile::builder_testnet(
        "svc", account, "n-svc", "n-acct",
    )
    .with_noop_engine()
    .build();
    p.rpc_url = rpc_url.to_owned();
    p.submit_timeout_seconds = Some(1);
    install_test_audit_key(&mut p);
    p
}

/// Every audit row the profile's log holds.
///
/// # Panics
///
/// Panics if a line is not JSON.
#[must_use]
#[allow(
    dead_code,
    reason = "shared across integration-test binaries; unused in some"
)]
pub fn audit_rows(
    profile: &stellar_agent_core::profile::schema::Profile,
) -> Vec<serde_json::Value> {
    let raw = std::fs::read_to_string(&profile.audit_log_path).unwrap_or_default();
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("each audit row must be JSON"))
        .collect()
}

/// The rows of `kind`.
#[must_use]
#[allow(
    dead_code,
    reason = "shared across integration-test binaries; unused in some"
)]
pub fn rows_of_kind<'a>(rows: &'a [serde_json::Value], kind: &str) -> Vec<&'a serde_json::Value> {
    rows.iter()
        .filter(|row| row.get("kind").and_then(serde_json::Value::as_str) == Some(kind))
        .collect()
}
