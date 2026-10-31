//! A halted profile refuses every tool call that is not read-only, through
//! the server's `tools/call` entry point, before any signer read or RPC
//! request.
//!
//! Each test serves a [`WalletServer`] over an in-memory duplex stream and
//! speaks JSON-RPC to it, so every call takes the same path a client's call
//! takes. The profile's endpoint is a mock server that records every request,
//! and the keyring is a mock store with a read hook on the signer coordinate,
//! so a refused call proves it sent nothing and loaded no key.
//!
//! The tools under test come from the server's own descriptors, so a tool
//! added later is covered without editing this file.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in integration tests"
)]

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rmcp::ServiceExt as _;
use serde_json::{Value, json};
use serial_test::serial;
use stellar_agent_core::policy::ToolValueKind;
use stellar_agent_core::profile::halt::{self, HaltMarker};
use stellar_agent_core::profile::loader;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::WalletServer;
use stellar_agent_test_support::{StellarAgentHomeGuard, keyring_mock};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

use crate::common::policy_mock::MockPolicyEngine;

/// Profile name every test serves.
const PROFILE: &str = "halt-e2e";

/// Keyring service of the profile's signer.
const SIGNER_SERVICE: &str = "halt-e2e-signer";

/// The profile's signer account.
const SIGNER_ACCOUNT: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";

/// A JSON-RPC client over the client half of a duplex stream.
struct Client {
    write: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    lines: tokio::io::Lines<BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>>,
    next_id: u64,
}

impl Client {
    /// Serves `server` on a fresh duplex stream and completes the MCP
    /// initialization handshake.
    async fn connect(server: WalletServer) -> Self {
        let (client_side, server_side) = tokio::io::duplex(1 << 20);
        let (server_read, server_write) = tokio::io::split(server_side);
        tokio::spawn(async move {
            let service = server
                .serve((server_read, server_write))
                .await
                .expect("server initializes");
            let _ = service.waiting().await;
        });
        let (read, write) = tokio::io::split(client_side);
        let mut client = Self {
            write,
            lines: BufReader::new(read).lines(),
            next_id: 1,
        };
        let init = client
            .request(
                "initialize",
                json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": { "name": "halt-integration", "version": "0" },
                }),
            )
            .await;
        assert!(init.get("result").is_some(), "initialize failed: {init}");
        client
            .send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
            .await;
        client
    }

    async fn send(&mut self, message: &Value) {
        let mut line = serde_json::to_vec(message).unwrap();
        line.push(b'\n');
        self.write.write_all(&line).await.unwrap();
        self.write.flush().await.unwrap();
    }

    /// Sends one request and returns its response, skipping notifications.
    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }))
            .await;
        loop {
            let line =
                tokio::time::timeout(std::time::Duration::from_secs(30), self.lines.next_line())
                    .await
                    .expect("the server answers within the timeout")
                    .unwrap()
                    .expect("the server keeps the stream open");
            let message: Value = serde_json::from_str(&line).unwrap();
            if message["id"] == json!(id) {
                return message;
            }
        }
    }

    /// Calls `tool` with `arguments` and returns the JSON-RPC response.
    async fn call(&mut self, tool: &str, arguments: Value) -> Value {
        self.request(
            "tools/call",
            json!({ "name": tool, "arguments": arguments }),
        )
        .await
    }
}

/// The business-envelope error code of a `tools/call` response, or `None`
/// when the response is not a business error.
fn envelope_code(response: &Value) -> Option<String> {
    let result = response.get("result")?;
    if result["isError"] != json!(true) {
        return None;
    }
    let text = result["content"][0]["text"].as_str()?;
    let envelope: Value = serde_json::from_str(text).ok()?;
    envelope["error"]["code"].as_str().map(str::to_owned)
}

/// The business-envelope error message of a `tools/call` response.
fn envelope_message(response: &Value) -> String {
    let text = response["result"]["content"][0]["text"].as_str().unwrap();
    let envelope: Value = serde_json::from_str(text).unwrap();
    envelope["error"]["message"].as_str().unwrap().to_owned()
}

/// Everything one test holds for the lifetime of its server.
struct Fixture {
    root: tempfile::TempDir,
    _home: StellarAgentHomeGuard,
    rpc: wiremock::MockServer,
    signer_reads: Arc<AtomicUsize>,
    profile: Profile,
}

impl Fixture {
    async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let home = StellarAgentHomeGuard::new(root.path());
        let rpc = wiremock::MockServer::start().await;
        let signer_reads = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&signer_reads);
        keyring_mock::install_with_read_hooks(vec![keyring_mock::ReadHook::new(
            SIGNER_SERVICE,
            SIGNER_ACCOUNT,
            Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }),
        )])
        .unwrap();
        let profile =
            Profile::builder_testnet(SIGNER_SERVICE, SIGNER_ACCOUNT, "halt-e2e-nonce", "default")
                .with_profile_name(PROFILE)
                .rpc_url(rpc.uri())
                .audit_log_path(root.path().join("audit").join(format!("{PROFILE}.jsonl")))
                .with_noop_engine()
                .build();
        loader::save(PROFILE, &profile).unwrap();
        Self {
            root,
            _home: home,
            rpc,
            signer_reads,
            profile,
        }
    }

    fn data_root(&self) -> &Path {
        self.root.path()
    }

    /// A server on the profile whose policy engine denies every call.
    fn server(&self) -> WalletServer {
        self.server_with(MockPolicyEngine::deny_no_matching_rule())
    }

    /// A server on the profile with `engine` as its policy engine.
    fn server_with(&self, engine: MockPolicyEngine) -> WalletServer {
        let mut server = WalletServer::new(self.profile.clone()).unwrap();
        assert_eq!(server.profile_name_for_approval(), PROFILE);
        server.set_policy_engine_for_test(Arc::new(engine));
        server
    }

    fn halt(&self, reason: Option<&str>) {
        let marker =
            HaltMarker::new("2026-10-31T12:00:00Z".to_owned(), reason.map(str::to_owned)).unwrap();
        halt::write_halt(self.data_root(), PROFILE, &marker).unwrap();
    }

    fn signer_reads(&self) -> usize {
        self.signer_reads.load(Ordering::SeqCst)
    }

    async fn rpc_requests(&self) -> usize {
        self.rpc.received_requests().await.unwrap().len()
    }
}

/// The tools a halt refuses, read from the server's descriptors: every tool
/// that does not declare itself read-only on both axes.
fn tools_a_halt_refuses(server: &WalletServer) -> Vec<String> {
    let mut tools: Vec<String> = WalletServer::router_tool_names()
        .into_iter()
        .filter(|name| {
            let descriptor = server
                .tool_registry_descriptor(name)
                .unwrap_or_else(|| panic!("{name}: every routed tool has a descriptor"));
            !(descriptor.read_only_hint && descriptor.value_kind == ToolValueKind::ReadOnly)
        })
        .collect();
    tools.sort();
    tools
}

/// Arguments that pass argument parsing and the mainnet refusal of
/// `stellar_sep43_sign_message`, so a call that is not halted reaches the
/// policy gate.
fn sign_message_args() -> Value {
    json!({ "chain_id": "stellar:testnet", "message": "hello" })
}

#[tokio::test]
#[serial]
async fn every_tool_that_is_not_read_only_refuses_while_halted_without_signer_or_rpc() {
    let fixture = Fixture::new().await;
    fixture.halt(Some("suspected prompt injection"));
    let server = fixture.server();
    let tools = tools_a_halt_refuses(&server);
    for expected in [
        "stellar_pay_commit",
        "stellar_create_account_commit",
        "stellar_trustline_commit",
        "stellar_claim_commit",
        "stellar_rule_create_commit",
        "stellar_sep43_sign_transaction",
        "stellar_sep43_sign_auth_entry",
        "stellar_sep43_sign_message",
        "stellar_sep43_sign_and_submit_transaction",
        "stellar_sep53_sign_message",
        "stellar_x402_create_payment",
        "stellar_x402_authenticated_payment",
        "stellar_defindex_vault_deposit",
        "stellar_defindex_vault_withdraw",
        "stellar_dex_trade",
        "stellar_mpp_charge_commit",
        "stellar_mpp_charge_prepare",
        "stellar_mpp_record_receipt",
        "stellar_mpp_reconcile_transaction",
        "stellar_transaction_status",
        "stellar_friendbot",
    ] {
        assert!(
            tools.contains(&expected.to_owned()),
            "{expected} is a tool a halt must refuse; the descriptor-derived list is {tools:?}"
        );
    }
    let mut client = Client::connect(server).await;

    for tool in &tools {
        // Empty arguments: a refusal before argument parsing proves the check
        // runs before the handler.
        let response = client.call(tool, json!({})).await;
        assert_eq!(
            envelope_code(&response).as_deref(),
            Some(halt::HALTED_CODE),
            "{tool}: {response}"
        );
        assert_eq!(
            envelope_message(&response),
            format!(
                "profile \"{PROFILE}\" is halted since 2026-10-31T12:00:00Z: suspected prompt \
                 injection; run \"stellar-agent profile resume --profile {PROFILE}\" to lift it"
            ),
            "{tool}"
        );
    }

    // A toolset action names the tool it routes to; a signing action refuses
    // although the toolset tool itself is read-only.
    for action in [
        "stellar_pay_commit",
        "stellar_rule_create_commit",
        "stellar_pay",
    ] {
        let response = client
            .call(
                "stellar_toolset_invoke",
                json!({ "toolset": "any-toolset", "action": action, "args": {} }),
            )
            .await;
        assert_eq!(
            envelope_code(&response).as_deref(),
            Some(halt::HALTED_CODE),
            "toolset action {action}: {response}"
        );
    }

    assert_eq!(fixture.signer_reads(), 0, "a halted call reads no signer");
    assert_eq!(
        fixture.rpc_requests().await,
        0,
        "a halted call sends no request"
    );
}

#[tokio::test]
#[serial]
async fn read_only_tools_and_the_profile_resource_answer_while_halted() {
    let fixture = Fixture::new().await;
    fixture.halt(None);
    let mut client = Client::connect(fixture.server_with(MockPolicyEngine::allow())).await;

    let response = client
        .call(
            "stellar_sep43_get_network",
            json!({ "chain_id": "stellar:testnet" }),
        )
        .await;
    assert_eq!(
        response["result"]["isError"],
        json!(false),
        "a read-only tool answers while halted: {response}"
    );

    // A read-only toolset action is not refused by the halt; it fails on the
    // missing toolset instead.
    let response = client
        .call(
            "stellar_toolset_invoke",
            json!({ "toolset": "absent-toolset", "action": "stellar_balances", "args": {} }),
        )
        .await;
    assert_ne!(
        envelope_code(&response).as_deref(),
        Some(halt::HALTED_CODE),
        "a read-only toolset action is not halted: {response}"
    );

    let response = client
        .request(
            "resources/read",
            json!({ "uri": format!("mcp-resource://profiles/{PROFILE}") }),
        )
        .await;
    let text = response["result"]["contents"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("the profile resource answers: {response}"));
    let metadata: Value = serde_json::from_str(text).unwrap();
    assert_eq!(metadata["halted"], true, "{metadata}");
    assert_eq!(metadata["halted_at"], "2026-10-31T12:00:00Z", "{metadata}");
    assert_eq!(metadata["mcp_disabled"], false, "{metadata}");

    assert_eq!(fixture.signer_reads(), 0);
    assert_eq!(fixture.rpc_requests().await, 0);
}

#[tokio::test]
#[serial]
async fn a_halt_lifted_on_a_running_server_lets_the_next_call_reach_the_policy_gate() {
    let fixture = Fixture::new().await;
    fixture.halt(None);
    let mut client = Client::connect(fixture.server()).await;

    let response = client
        .call("stellar_sep43_sign_message", sign_message_args())
        .await;
    assert_eq!(
        envelope_code(&response).as_deref(),
        Some(halt::HALTED_CODE),
        "{response}"
    );

    assert!(halt::clear_halt(fixture.data_root(), PROFILE).unwrap());

    let response = client
        .call("stellar_sep43_sign_message", sign_message_args())
        .await;
    assert_eq!(
        envelope_code(&response).as_deref(),
        Some("policy.deny.no_matching_rule"),
        "after the halt is lifted the call passes the halt check and the deny-all \
         engine refuses it: {response}"
    );

    let response = client
        .request(
            "resources/read",
            json!({ "uri": format!("mcp-resource://profiles/{PROFILE}") }),
        )
        .await;
    let metadata: Value =
        serde_json::from_str(response["result"]["contents"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(metadata["halted"], false, "{metadata}");
    assert!(metadata["halted_at"].is_null(), "{metadata}");

    assert_eq!(fixture.signer_reads(), 0, "the denied call reads no signer");
}

#[tokio::test]
#[serial]
async fn a_halt_set_on_a_running_server_refuses_the_next_call() {
    let fixture = Fixture::new().await;
    let mut client = Client::connect(fixture.server()).await;

    let response = client
        .call("stellar_sep43_sign_message", sign_message_args())
        .await;
    assert_eq!(
        envelope_code(&response).as_deref(),
        Some("policy.deny.no_matching_rule"),
        "a profile that is not halted reaches the policy gate: {response}"
    );

    fixture.halt(Some("operator stop"));

    let response = client
        .call("stellar_sep43_sign_message", sign_message_args())
        .await;
    assert_eq!(
        envelope_code(&response).as_deref(),
        Some(halt::HALTED_CODE),
        "{response}"
    );
    assert!(envelope_message(&response).contains(": operator stop;"));
    assert_eq!(fixture.signer_reads(), 0);
}

#[tokio::test]
#[serial]
async fn an_unreadable_marker_refuses_without_a_signer_read() {
    let fixture = Fixture::new().await;
    std::fs::create_dir_all(halt::halt_path(fixture.data_root(), PROFILE).unwrap()).unwrap();
    let mut client = Client::connect(fixture.server()).await;

    for tool in ["stellar_sep43_sign_message", "stellar_pay_commit"] {
        let arguments = if tool == "stellar_sep43_sign_message" {
            sign_message_args()
        } else {
            json!({})
        };
        let response = client.call(tool, arguments).await;
        assert_eq!(
            envelope_code(&response).as_deref(),
            Some(halt::HALT_UNREADABLE_CODE),
            "{tool}: {response}"
        );
    }

    let response = client
        .request(
            "resources/read",
            json!({ "uri": format!("mcp-resource://profiles/{PROFILE}") }),
        )
        .await;
    let metadata: Value =
        serde_json::from_str(response["result"]["contents"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        metadata["halted"], true,
        "an unreadable marker reads as halted: {metadata}"
    );
    assert!(metadata["halted_at"].is_null(), "{metadata}");

    assert_eq!(fixture.signer_reads(), 0);
    assert_eq!(fixture.rpc_requests().await, 0);
}

/// The two witnesses the halted tests read count real work: an unhalted
/// signing call under an allow engine reads the signer once, and a call that
/// reaches the network sends its request to the profile's endpoint, where the
/// mock records it. Once the profile is halted, the signing call moves
/// neither count.
#[tokio::test]
#[serial]
async fn the_signer_read_and_request_witnesses_count_an_unhalted_call() {
    let fixture = Fixture::new().await;
    let mut client = Client::connect(fixture.server_with(MockPolicyEngine::allow())).await;

    let response = client
        .call("stellar_sep43_sign_message", sign_message_args())
        .await;
    assert_ne!(
        envelope_code(&response).as_deref(),
        Some(halt::HALTED_CODE),
        "{response}"
    );
    assert_eq!(
        fixture.signer_reads(),
        1,
        "an allowed signing call reads its signer once: {response}"
    );
    let response = client
        .call(
            "stellar_fee_stats",
            json!({ "chain_id": "stellar:testnet" }),
        )
        .await;
    let requests = fixture.rpc_requests().await;
    assert!(
        requests > 0,
        "a call that reaches the network is recorded at the profile's endpoint: {response}"
    );

    fixture.halt(None);
    let response = client
        .call("stellar_sep43_sign_message", sign_message_args())
        .await;
    assert_eq!(
        envelope_code(&response).as_deref(),
        Some(halt::HALTED_CODE),
        "{response}"
    );
    assert_eq!(fixture.signer_reads(), 1, "the halted call reads no signer");
    assert_eq!(
        fixture.rpc_requests().await,
        requests,
        "the halted call sends no request"
    );
}
