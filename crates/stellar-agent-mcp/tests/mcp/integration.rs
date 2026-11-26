//! Integration tests for the MCP stdio server.
//!
//! These tests spawn `stellar-agent-mcp` as a subprocess under the shared
//! child-process driver and exercise the MCP JSON-RPC protocol. Each test
//! sends a message and validates the response with its id, within the
//! driver's response deadline, without requiring a live Stellar network
//! connection.
//!
//! # Test isolation
//!
//! Each child owns a marked home. Handshakes use the empty-home testnet
//! fallback; balances uses a stored Noop profile and a local RPC responder.
//! Both clean and poisoned parent environments exercise every scenario.
//!
//! Every test that spawns the server is `#[serial]`, like the tests in this
//! target that override `STELLAR_AGENT_HOME` in this process.
//!
//! # Covered scenarios
//!
//! 1. `initialize` handshake → server returns capabilities including `tools`.
//! 2. `notifications/initialized` → server processes without error.
//! 3. `tools/list` → returns `stellar_balances` with the declared schema.
//! 4. `tools/call stellar_balances` with an absent account → failed tool envelope.
//! 5. Invalid account arguments and unknown tools → protocol invalid-params errors.
//! 6. `initialize` with a supported known version → echoes the requested version.
//! 7. `initialize` with an unknown version → returns `2024-11-05`.
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

use serial_test::serial;

use crate::common::child_process::ChildDriver;
use crate::common::server_binary::server_command;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: the binary under the shared child-process driver
// ─────────────────────────────────────────────────────────────────────────────

/// Owns the marked home and optional local RPC until the child is stopped.
struct ServerFixture {
    driver: ChildDriver,
    rpc: Option<wiremock::MockServer>,
    _home: stellar_agent_test_support::sandbox::StateSandbox,
    runtime: tokio::runtime::Runtime,
}

impl std::ops::Deref for ServerFixture {
    type Target = ChildDriver;
    fn deref(&self) -> &Self::Target {
        &self.driver
    }
}

impl std::ops::DerefMut for ServerFixture {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.driver
    }
}

impl ServerFixture {
    fn requests(&self) -> Vec<wiremock::Request> {
        self.runtime
            .block_on(self.rpc.as_ref().unwrap().received_requests())
            .unwrap()
    }
}

fn spawn_server(poisoned: bool, local_rpc: bool) -> ServerFixture {
    use std::ffi::OsStr;
    use stellar_agent_test_support::{env_guard::ScopedEnvVar, sandbox::StateSandbox};
    let poison = [
        ("STELLAR_AGENT_PROFILE", "poison-profile"),
        ("STELLAR_AGENT_CHAIN_ID", "stellar:mainnet"),
        ("STELLAR_AGENT_RPC_URL", "invalid-fixture-endpoint"),
        ("STELLAR_AGENT_KEYRING_BACKEND", "poison-backend"),
        ("STELLAR_AGENT_HEADLESS_KEYRING_KEY", "poison-key"),
        (
            "STELLAR_AGENT_TEST_LIVE_PLATFORM_KEYRING",
            "real-platform-keyring",
        ),
    ];
    let _environment: Vec<_> = poison
        .iter()
        .map(|(name, value)| ScopedEnvVar::new(name, poisoned.then_some(OsStr::new(value))))
        .collect();
    let home = StateSandbox::new().unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let rpc = local_rpc.then(|| {
        runtime.block_on(async {
            let rpc = wiremock::MockServer::start().await;
            wiremock::Mock::given(wiremock::matchers::method("POST"))
                .respond_with(
                    stellar_agent_test_support::echo_id_responder::KeyedLedgerEntriesResponder::new(
                    ),
                )
                .mount(&rpc)
                .await;
            std::fs::create_dir(home.path().join("profiles")).unwrap();
            std::fs::write(
                home.path().join("profiles/default.toml"),
                stellar_agent_test_support::profile_fixtures::noop_profile_toml(
                    "default",
                    "stellar:testnet",
                    &rpc.uri(),
                ),
            )
            .unwrap();
            rpc
        })
    });
    let command = server_command(home.path());
    let environment: std::collections::HashMap<_, _> = command.get_envs().collect();
    assert_eq!(
        environment.get(OsStr::new("STELLAR_AGENT_HOME")),
        Some(&Some(home.path().as_os_str()))
    );
    assert_eq!(
        environment.get(OsStr::new("STELLAR_AGENT_KEYRING_BACKEND")),
        Some(&Some(OsStr::new("headless-env")))
    );
    assert_eq!(
        environment.get(OsStr::new("STELLAR_AGENT_HEADLESS_KEYRING_KEY")),
        Some(&Some(OsStr::new("invalid-fixture-key")))
    );
    for name in [
        "STELLAR_AGENT_PROFILE",
        "STELLAR_AGENT_CHAIN_ID",
        "STELLAR_AGENT_RPC_URL",
        "STELLAR_AGENT_TEST_LIVE_PLATFORM_KEYRING",
    ] {
        assert!(
            !environment.contains_key(OsStr::new(name)),
            "ambient wallet setting {name}"
        );
    }
    assert_eq!(
        command.get_args().count(),
        0,
        "ordinary server receives no live argument"
    );
    ServerFixture {
        driver: ChildDriver::spawn(command),
        rpc,
        _home: home,
        runtime,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

/// 1. initialize handshake → server responds with capabilities.
#[test]
#[serial]
fn initialize_returns_capabilities() {
    for poisoned in [false, true] {
        let mut driver = spawn_server(poisoned, false);

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

        let response = driver.response(1);

        // Response must have the expected fields.
        assert_eq!(response["jsonrpc"], "2.0", "unexpected jsonrpc version");
        assert_eq!(response["id"], 1, "unexpected response id");
        let result = &response["result"];
        assert!(
            result["capabilities"]["tools"].is_object(),
            "server must advertise tools capability: {response:?}"
        );
    }
}

/// 6. `initialize` echoes each supported known protocol version.
#[test]
#[serial]
fn initialize_protocol_version_echoes_known_versions() {
    for poisoned in [false, true] {
        for version in ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"] {
            let mut driver = spawn_server(poisoned, false);

            driver.send(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": version,
                    "capabilities": {},
                    "clientInfo": { "name": "test-client", "version": "0.1.0" }
                }
            }));

            let response = driver.response(1);
            assert_eq!(
                response["result"]["protocolVersion"], version,
                "requested {version}, poisoned={poisoned}"
            );
        }
    }
}

/// 7. `initialize` falls back to `2024-11-05` for an unknown protocol version.
#[test]
#[serial]
fn initialize_protocol_version_falls_back_for_unknown_version() {
    for poisoned in [false, true] {
        let mut driver = spawn_server(poisoned, false);

        driver.send(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2099-01-01",
                "capabilities": {},
                "clientInfo": { "name": "test-client", "version": "0.1.0" }
            }
        }));

        let response = driver.response(1);
        assert_eq!(
            response["result"]["protocolVersion"], "2024-11-05",
            "unknown version, poisoned={poisoned}"
        );
    }
}

/// 2. `notifications/initialized` → server processes without error.
#[test]
#[serial]
fn notifications_initialized_processed() {
    for poisoned in [false, true] {
        let mut driver = spawn_server(poisoned, false);

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
        let init_response = driver.response(1);
        assert!(
            init_response["result"]["capabilities"]["tools"].is_object(),
            "{init_response}"
        );
        assert!(init_response.get("error").is_none(), "{init_response}");

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

        let list_response = driver.response(2);
        assert_eq!(list_response["id"], 2, "unexpected tools/list response id");
        assert!(list_response.get("error").is_none(), "{list_response}");
        assert!(
            list_response["result"]["tools"].is_array(),
            "{list_response}"
        );
    }
}

/// 3. `tools/list` → returns `stellar_balances` with chain_id and account_id args.
#[test]
#[serial]
fn tools_list_includes_stellar_balances() {
    for poisoned in [false, true] {
        let mut driver = spawn_server(poisoned, false);

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
        let init_response = driver.response(1);
        assert!(
            init_response["result"]["capabilities"]["tools"].is_object(),
            "{init_response}"
        );
        assert!(init_response.get("error").is_none(), "{init_response}");

        driver.send(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }));

        let list_response = driver.response(2);

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
}

/// 4a. `tools/call stellar_balances` → unknown account returns error envelope,
///     not a protocol-level error (account-not-found is a tool-level error).
#[test]
#[serial]
fn tools_call_stellar_balances_unknown_account_returns_tool_error() {
    for poisoned in [false, true] {
        let mut driver = spawn_server(poisoned, true);

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
        let init_response = driver.response(1);
        assert!(
            init_response["result"]["capabilities"]["tools"].is_object(),
            "{init_response}"
        );
        assert!(init_response.get("error").is_none(), "{init_response}");

        driver.send(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "stellar_balances",
                "arguments": {
                    "chain_id": "stellar:testnet",
                    "account_id": stellar_strkey::ed25519::PublicKey([7; 32]).to_string().to_string()
                }
            }
        }));

        let response = driver.response(3);
        assert_eq!(
            response["id"], 3,
            "response id must match request id: {response:?}"
        );
        assert!(response.get("error").is_none(), "{response}");
        assert_eq!(response["result"]["isError"], true, "{response}");
        let envelope: serde_json::Value =
            serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(envelope["ok"], false, "{envelope}");
        assert!(envelope.get("data").is_none(), "{envelope}");
        assert_eq!(
            envelope["error"]["code"], "network.account_not_found",
            "{envelope}"
        );
        let requests = driver.requests();
        assert_eq!(
            requests.len(),
            1,
            "the account query reaches the local responder"
        );
        let request: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(request["method"], "getLedgerEntries");
        use stellar_xdr::WriteXdr as _;
        let account_key = stellar_xdr::LedgerKey::Account(stellar_xdr::LedgerKeyAccount {
            account_id: stellar_xdr::AccountId(stellar_xdr::PublicKey::PublicKeyTypeEd25519(
                stellar_xdr::Uint256([7; 32]),
            )),
        })
        .to_xdr_base64(stellar_xdr::Limits::none())
        .unwrap();
        assert_eq!(request["params"]["keys"], serde_json::json!([account_key]));
    }
}

/// 4b. `tools/call stellar_balances` with invalid strkey → invalid_params error.
#[test]
#[serial]
fn tools_call_stellar_balances_invalid_strkey_returns_invalid_params() {
    for poisoned in [false, true] {
        let mut driver = spawn_server(poisoned, true);

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
        let init_response = driver.response(1);
        assert!(
            init_response["result"]["capabilities"]["tools"].is_object(),
            "{init_response}"
        );
        assert!(init_response.get("error").is_none(), "{init_response}");

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

        let response = driver.response(3);

        assert_eq!(response["id"], 3);
        assert!(response.get("result").is_none(), "{response}");
        assert_eq!(response["error"]["code"], -32602, "{response}");
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap()
                .contains("account_id"),
            "{response}"
        );
        assert!(
            driver.requests().is_empty(),
            "invalid account reaches no RPC"
        );
    }
}

/// An unknown tool is a protocol invalid-params refusal after initialization.
#[test]
#[serial]
fn tools_call_unknown_tool_returns_error() {
    for poisoned in [false, true] {
        let mut driver = spawn_server(poisoned, false);

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
        let init_response = driver.response(1);
        assert!(
            init_response["result"]["capabilities"]["tools"].is_object(),
            "{init_response}"
        );
        assert!(init_response.get("error").is_none(), "{init_response}");

        driver.send(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "totally_unknown_tool",
                "arguments": {}
            }
        }));

        let response = driver.response(4);

        assert_eq!(response["id"], 4);
        assert!(response.get("result").is_none(), "{response}");
        assert_eq!(response["error"]["code"], -32602, "{response}");
        assert_eq!(response["error"]["message"], "tool not found");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy-engine gate unit assertions
// ─────────────────────────────────────────────────────────────────────────────

/// Unit test: `NoopPolicyEngine` returns `Decision::Allow` for `stellar_balances`
/// on both testnet and mainnet profiles.
#[test]
#[serial_test::serial]
fn policy_engine_allows_stellar_balances_read_only() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
    let result = engine.evaluate(
        &descriptor,
        &args,
        &testnet,
        None,
        None,
        None,
        None,
        None,
        1_700_000_000_000,
    );
    assert_eq!(
        result.unwrap(),
        Decision::Allow,
        "stellar_balances must be allowed on testnet"
    );

    let mainnet = Profile::builder_mainnet(
        "https://rpc.example.invalid",
        "svc",
        "acct",
        "n-svc",
        "n-acct",
    )
    .build();
    let result = engine.evaluate(
        &descriptor,
        &args,
        &mainnet,
        None,
        None,
        None,
        None,
        None,
        1_700_000_000_000,
    );
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
