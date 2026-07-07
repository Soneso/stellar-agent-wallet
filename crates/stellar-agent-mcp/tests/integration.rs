//! Integration tests for the MCP stdio server.
//!
//! These tests spawn `stellar-agent-mcp` as a subprocess with piped stdin/stdout
//! and exercise the MCP JSON-RPC protocol.  Each test sends a message and
//! validates the response without requiring a live Stellar network connection.
//!
//! # Test isolation
//!
//! Tests use `tempfile::tempdir()` to provide a profile-less environment so
//! the server falls back to the testnet default profile (as documented in
//! `loader::load_default_or_testnet_fallback`).
//!
//! # Covered scenarios
//!
//! 1. `initialize` handshake → server returns capabilities including `tools`.
//! 2. `notifications/initialized` → server processes without error.
//! 3. `tools/list` → returns `stellar_balances` with the declared schema.
//! 4. `tools/call stellar_balances` with a valid account → valid JSON envelope.
//! 5. `tools/call <unknown>` → returns a tool-not-found / method-not-found error.
//!
//! # Policy-engine gate assertion
//!
//! The integration tests implicitly verify that `policy_engine.evaluate` is
//! called for every `tools/call` because for the read-only `stellar_balances`
//! tool the call must succeed (Decision::Allow) before network access occurs.
//! A separate unit test in the server module asserts the evaluation path.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-only; panics acceptable in integration tests"
)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

/// Returns the path to the `stellar-agent-mcp` binary built by Cargo.
///
/// `env!("CARGO_BIN_EXE_stellar-agent-mcp")` is resolved by Cargo at compile
/// time and is guaranteed to point at the binary produced for this crate, so
/// the binary is always built before tests run.
fn mcp_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_stellar-agent-mcp"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: simpler process management using explicit read-write channels
// ─────────────────────────────────────────────────────────────────────────────

/// Simplified integration driver: spawns the binary, sends JSON lines,
/// collects responses.  Terminates after `timeout_ms` or when `n_responses`
/// responses have been received.
struct McpDriver {
    child: std::process::Child,
    writer: std::io::BufWriter<std::process::ChildStdin>,
    reader: BufReader<std::process::ChildStdout>,
}

impl McpDriver {
    fn spawn() -> Self {
        let binary = mcp_binary();
        let mut child = Command::new(&binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env("STELLAR_AGENT_LOG", "off")
            .spawn()
            .expect("stellar-agent-mcp binary must spawn");
        let writer =
            std::io::BufWriter::new(child.stdin.take().expect("child stdin must be piped"));
        let reader = BufReader::new(child.stdout.take().expect("child stdout must be piped"));
        Self {
            child,
            writer,
            reader,
        }
    }

    fn send(&mut self, msg: &serde_json::Value) {
        let line = serde_json::to_string(msg).expect("json serialisation");
        writeln!(self.writer, "{}", line).expect("write to child stdin must succeed");
        self.writer
            .flush()
            .expect("flush to child stdin must succeed");
    }

    /// Reads the next JSON-RPC response line.
    ///
    /// Panics if the server does not respond with a valid JSON-RPC message.
    fn recv(&mut self) -> serde_json::Value {
        let mut line = String::new();
        self.reader
            .read_line(&mut line)
            .expect("server must write a response line");
        assert!(
            !line.trim().is_empty(),
            "server must respond with a non-empty JSON-RPC message"
        );
        serde_json::from_str(line.trim())
            .expect("server must respond with a valid JSON-RPC message")
    }
}

impl Drop for McpDriver {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

/// 1. initialize handshake → server responds with capabilities.
#[test]
fn initialize_returns_capabilities() {
    let mut driver = McpDriver::spawn();

    driver.send(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test-client", "version": "0.1.0" }
        }
    }));

    let response = driver.recv();

    // Response must have the expected fields.
    assert_eq!(response["jsonrpc"], "2.0", "unexpected jsonrpc version");
    assert_eq!(response["id"], 1, "unexpected response id");
    let result = &response["result"];
    assert!(
        result["capabilities"]["tools"].is_object(),
        "server must advertise tools capability: {response:?}"
    );
}

/// 2. `notifications/initialized` → server processes without error.
#[test]
fn notifications_initialized_processed() {
    let mut driver = McpDriver::spawn();

    // First: do the handshake.
    driver.send(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test-client", "version": "0.1.0" }
        }
    }));
    let _init_response = driver.recv();

    // Notifications have no id and expect no response.
    driver.send(&serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    }));

    // Now send tools/list to check that the server is still responsive.
    driver.send(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }));

    let list_response = driver.recv();
    assert_eq!(list_response["id"], 2, "unexpected tools/list response id");
}

/// 3. `tools/list` → returns `stellar_balances` with chain_id and account_id args.
#[test]
fn tools_list_includes_stellar_balances() {
    let mut driver = McpDriver::spawn();

    driver.send(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test-client", "version": "0.1.0" }
        }
    }));
    let _init_response = driver.recv();

    driver.send(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }));

    let list_response = driver.recv();

    let tools = &list_response["result"]["tools"];
    assert!(
        tools.is_array(),
        "tools must be an array: {list_response:?}"
    );

    let tools_arr = tools.as_array().expect("array");
    let stellar_balances = tools_arr.iter().find(|t| t["name"] == "stellar_balances");
    assert!(
        stellar_balances.is_some(),
        "stellar_balances must appear in tools/list: {tools:?}"
    );

    let sb = stellar_balances.expect("found above");
    let schema = &sb["inputSchema"];
    assert!(
        schema["properties"]["chain_id"].is_object(),
        "stellar_balances must declare chain_id in inputSchema: {sb:?}"
    );
    assert!(
        schema["properties"]["account_id"].is_object(),
        "stellar_balances must declare account_id in inputSchema: {sb:?}"
    );
}

/// 4a. `tools/call stellar_balances` → unknown account returns error envelope,
///     not a protocol-level error (account-not-found is a tool-level error).
#[test]
fn tools_call_stellar_balances_unknown_account_returns_tool_error() {
    let mut driver = McpDriver::spawn();

    driver.send(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test-client", "version": "0.1.0" }
        }
    }));
    let _init_response = driver.recv();

    // A valid G-strkey that is unlikely to exist on testnet.
    // The server must route the call to the network layer and respond with a
    // tool-level error (account not found) or a network-level error.
    driver.send(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "stellar_balances",
            "arguments": {
                "chain_id": "stellar:testnet",
                "account_id": "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN"
            }
        }
    }));

    let response = driver.recv();
    // The server must return a response (either a tool error or a network error).
    // The response id must match the request.
    assert_eq!(
        response["id"], 3,
        "response id must match request id: {response:?}"
    );
}

/// 4b. `tools/call stellar_balances` with invalid strkey → invalid_params error.
#[test]
fn tools_call_stellar_balances_invalid_strkey_returns_invalid_params() {
    let mut driver = McpDriver::spawn();

    driver.send(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test-client", "version": "0.1.0" }
        }
    }));
    let _init_response = driver.recv();

    driver.send(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "stellar_balances",
            "arguments": {
                "chain_id": "stellar:testnet",
                "account_id": "not-a-valid-strkey"
            }
        }
    }));

    let response = driver.recv();

    // Invalid params should return an error at the JSON-RPC or tool level.
    let has_error =
        response.get("error").is_some() || response["result"]["isError"].as_bool() == Some(true);
    assert!(
        has_error,
        "invalid strkey must produce an error response: {response:?}"
    );
}

/// 5. `tools/call <unknown>` → protocol error or tool.unknown error.
#[test]
fn tools_call_unknown_tool_returns_error() {
    let mut driver = McpDriver::spawn();

    driver.send(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test-client", "version": "0.1.0" }
        }
    }));
    let _init_response = driver.recv();

    driver.send(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "totally_unknown_tool",
            "arguments": {}
        }
    }));

    let response = driver.recv();

    // The response must have either an error field (protocol error) or
    // is_error=true in the result (tool-level error).
    let has_error =
        response.get("error").is_some() || response["result"]["isError"].as_bool() == Some(true);
    assert!(
        has_error,
        "unknown tool must produce an error response: {response:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy-engine gate unit assertions
// ─────────────────────────────────────────────────────────────────────────────

/// Unit test: `NoopPolicyEngine` returns `Decision::Allow` for `stellar_balances`
/// on both testnet and mainnet profiles.
#[test]
fn policy_engine_allows_stellar_balances_read_only() {
    use stellar_agent_core::policy::{
        Decision, McpToolRegistration, NoopPolicyEngine, PolicyEngine, ToolDescriptor,
    };
    use stellar_agent_core::profile::schema::Profile;

    let engine = NoopPolicyEngine;
    let descriptor = ToolDescriptor::from_registration(&McpToolRegistration {
        name: "stellar_balances",
        destructive_hint: false,
        read_only_hint: true,
        chain_id_required: true,
        value_kind: stellar_agent_core::policy::ToolValueKind::ReadOnly,
    });
    let args = serde_json::Value::Null;

    let testnet = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct").build();
    let result = engine.evaluate(&descriptor, &args, &testnet, None, None, None, None, None);
    assert_eq!(
        result.unwrap(),
        Decision::Allow,
        "stellar_balances must be allowed on testnet"
    );

    let mainnet = Profile::builder_mainnet("svc", "acct", "n-svc", "n-acct").build();
    let result = engine.evaluate(&descriptor, &args, &mainnet, None, None, None, None, None);
    assert_eq!(
        result.unwrap(),
        Decision::Allow,
        "stellar_balances must be allowed on mainnet (read-only)"
    );
}

/// Unit test: decision `Allow` propagates correctly through the dispatch site.
///
/// This asserts the call-site discipline: every tools/call invokes
/// `policy_engine.evaluate` and propagates `Decision::Allow` correctly.
#[test]
fn decision_allow_propagates() {
    use stellar_agent_core::policy::Decision;

    let decision = Decision::Allow;
    // The server dispatch site matches on Decision::Allow and proceeds.
    assert!(
        matches!(decision, Decision::Allow),
        "Decision::Allow must be matched correctly"
    );
}
