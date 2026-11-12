//! A halted profile refuses every tool call that is not read-only, through
//! the server's `tools/call` entry point, before any signer read or RPC
//! request.
//!
//! Most tests serve a [`WalletServer`] over an in-memory duplex stream and
//! speak JSON-RPC to it, so every call takes the same path a client's call
//! takes. The profile's endpoint is a mock server that records every request,
//! and the keyring is a mock store with a read hook on the signer coordinate,
//! so a refused call proves it sent nothing and loaded no key.
//!
//! The binary tests drive the real server over stdio through the shared
//! child-process driver. They queue a `profile_halted` row in the audit outbox
//! while the server holds the keyed writer. Then they close stdin or deliver a
//! shutdown event, and assert the server drains the row into the log before it
//! exits. On Unix, a second SIGINT or SIGTERM during the shutdown wait or the
//! exit drain ends the process with exit code 3 and leaves the row queued. On
//! Windows, a real Ctrl-Break or console close reaches a server in its own
//! console.
//!
//! Three more tests drive `serve_on_until` over a duplex stream. A shutdown
//! future stops a live session, and the shutdown wait bounds a session that
//! cannot stop. A shutdown before initialization returns cleanly.
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
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rmcp::ServiceExt as _;
use serde_json::{Value, json};
use serial_test::serial;
use stellar_agent_core::audit_log::outbox::OUTBOX_LOCK_WAIT_ENV;
use stellar_agent_core::audit_log::{AuditEntry, AuditOutbox, inspect_outbox};
use stellar_agent_core::policy::ToolValueKind;
use stellar_agent_core::profile::halt::{self, HaltMarker};
use stellar_agent_core::profile::loader;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::WalletServer;
use stellar_agent_mcp::transport::{BoundedTransport, SHUTDOWN_WAIT, serve_on_until};
use stellar_agent_network::keyring::KeyringTipAnchorStore;
use stellar_agent_test_support::keyring_mock::DefaultStoreGuard;
use stellar_agent_test_support::{StellarAgentHomeGuard, keyring_mock};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};

use crate::common::child_process::ChildDriver;
#[cfg(windows)]
use crate::common::child_process::{EXIT_DEADLINE, StderrWait};
use crate::common::policy_mock::MockPolicyEngine;

/// Profile name every test serves.
const PROFILE: &str = "halt-e2e";

/// Keyring service of the profile's signer.
const SIGNER_SERVICE: &str = "halt-e2e-signer";

/// The profile's signer account.
const SIGNER_ACCOUNT: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";

/// The profile's audit chain-root key.
const AUDIT_KEY: [u8; 32] = [0x5a; 32];

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
        Self::over(client_side).await
    }

    /// Completes the MCP initialization handshake on `client_side`.
    async fn over(client_side: tokio::io::DuplexStream) -> Self {
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
        // A signing call acquires the keyed audit writer before it reads the
        // signer, so the profile carries its audit chain-root key.
        let audit_key = &profile.audit_log_hash_chain_key_id;
        keyring_core::Entry::new(&audit_key.service, &audit_key.account)
            .unwrap()
            .set_password(&base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                AUDIT_KEY,
            ))
            .unwrap();
        loader::save(PROFILE, &profile).unwrap();
        // The signer is enrolled: its identity record is stored, so an
        // allowed signing call reaches the seed read the hook counts.
        crate::common::store_named_signer_identity(
            PROFILE,
            SIGNER_SERVICE,
            SIGNER_ACCOUNT,
            [0x48; 32],
        );
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

    // A toolset action names the tool it routes to, and that tool's
    // descriptor decides: a signing action refuses.
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

/// A resolved shutdown future cancels a live session while its client stays
/// connected, and the session stops before the fallback wait expires.
#[tokio::test]
#[serial]
async fn serve_on_until_returns_after_the_shutdown_future_resolves() {
    let server = WalletServer::new(
        Profile::builder_testnet_named("shutdown-future", "svc", "acct", "nonce-svc", "nonce-acct")
            .with_noop_engine()
            .build(),
    )
    .unwrap();
    let (client_side, server_side) = tokio::io::duplex(1 << 20);
    let (server_read, server_write) = tokio::io::split(server_side);
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        serve_on_until(
            server,
            BoundedTransport::over(server_read, server_write),
            async {
                let _ = rx.await;
            },
        )
        .await
        .map_err(|error| error.to_string())
    });
    let mut client = Client::over(client_side).await;
    // A response after initialization proves shutdown reaches the running session.
    let ping = client.request("ping", json!({})).await;
    assert!(ping.get("result").is_some(), "ping failed: {ping}");

    let signalled_at = Instant::now();
    tx.send(()).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("the serving task returns within ten seconds")
        .expect("the serving task joins");
    assert!(result.is_ok(), "the session stops cleanly: {result:?}");
    assert!(
        signalled_at.elapsed() < SHUTDOWN_WAIT,
        "cancellation stops the session before the shutdown wait expires"
    );
    drop(client);
}

/// A session whose write is blocked cannot stop on cancel; the shutdown wait
/// bounds it and the function returns on the warn path.
#[tokio::test]
#[serial]
async fn serve_on_until_returns_after_the_shutdown_wait_when_the_session_cannot_stop() {
    let server = WalletServer::new(
        Profile::builder_testnet_named("shutdown-wait", "svc", "acct", "nonce-svc", "nonce-acct")
            .with_noop_engine()
            .build(),
    )
    .unwrap();
    let (client_side, server_side) = tokio::io::duplex(256);
    let (server_read, server_write) = tokio::io::split(server_side);
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        serve_on_until(
            server,
            BoundedTransport::over(server_read, server_write),
            async {
                let _ = rx.await;
            },
        )
        .await
        .map_err(|error| error.to_string())
    });
    let mut client = Client::over(client_side).await;
    let ping = client.request("ping", json!({})).await;
    assert!(ping.get("result").is_some(), "ping failed: {ping}");

    // Reading one raw byte proves the tool-list response holds the write mutex.
    // The remaining response fills the buffer and blocks the write through cancellation.
    let id = client.next_id;
    client.next_id += 1;
    client
        .send(&json!({ "jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {} }))
        .await;
    let mut byte = [0];
    tokio::time::timeout(
        Duration::from_secs(30),
        client.lines.get_mut().get_mut().read_exact(&mut byte),
    )
    .await
    .expect("the reply write starts")
    .unwrap();

    let signalled_at = Instant::now();
    tx.send(()).unwrap();
    let result = tokio::time::timeout(SHUTDOWN_WAIT + Duration::from_secs(5), task)
        .await
        .expect("the serving task returns within the shutdown wait plus five seconds")
        .expect("the serving task joins");
    assert!(
        result.is_ok(),
        "the warn path returns successfully: {result:?}"
    );
    assert!(
        signalled_at.elapsed() >= SHUTDOWN_WAIT,
        "the blocked session reaches the shutdown wait"
    );
    drop(client);
}

/// The source of the transport, which passes one cancellation token to rmcp.
const TRANSPORT_SOURCE: &str = include_str!("../../src/transport.rs");

/// A shutdown that resolves before the client sends `initialize` cancels the
/// handshake through the session's one cancellation token. The function
/// returns `Ok(())` with the pre-session log line, not a handshake failure.
#[tokio::test]
#[serial]
async fn serve_on_until_returns_before_initialization_on_shutdown() {
    assert_eq!(
        TRANSPORT_SOURCE.matches(".serve_with_ct(").count(),
        1,
        "one token reaches rmcp for the whole session"
    );
    let capture = stellar_agent_test_support::CaptureWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .with_writer(capture.clone())
        .finish();
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();

    let server = WalletServer::new(
        Profile::builder_testnet_named("shutdown-early", "svc", "acct", "nonce-svc", "nonce-acct")
            .with_noop_engine()
            .build(),
    )
    .unwrap();
    let (client_side, server_side) = tokio::io::duplex(1 << 20);
    let (server_read, server_write) = tokio::io::split(server_side);
    let (tx, rx) = tokio::sync::oneshot::channel();
    // The client stays connected and sends nothing, so the handshake waits
    // for `initialize` when the shutdown resolves.
    tx.send(()).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        serve_on_until(
            server,
            BoundedTransport::over(server_read, server_write),
            async {
                let _ = rx.await;
            },
        ),
    )
    .await
    .expect("the cancelled handshake returns within ten seconds")
    .map_err(|error| error.to_string());

    assert_eq!(result, Ok(()), "a shutdown before initialization is clean");
    let logs = capture.captured_str();
    assert!(
        logs.contains("stellar-agent-mcp: shutdown signal received before the session started"),
        "{logs}"
    );
    assert!(!logs.contains("MCP server ready"), "{logs}");
    drop(client_side);
}

// ── The binary's exit drain ──────────────────────────────────────────────────

/// The key that seals the headless store the test process and the server child
/// share.
const HEADLESS_KEY: [u8; 32] = [0x6d; 32];

/// The file-backed keyring store at the path the child resolves from
/// `STELLAR_AGENT_HOME`.
fn headless_store_path(home: &Path) -> std::path::PathBuf {
    home.join("headless-keyring").join("store.keyring")
}

/// Installs the file-backed keyring store at the path the child resolves from
/// `STELLAR_AGENT_HOME` as this process's default store, until the returned
/// guard restores the previous one.
fn install_headless_store(home: &Path) -> DefaultStoreGuard {
    let store: Arc<keyring_core::CredentialStore> =
        Arc::new(stellar_agent_headless_keyring::store::HeadlessStore::new(
            headless_store_path(home),
            stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                zeroize::Zeroizing::new(HEADLESS_KEY),
            )),
        ));
    DefaultStoreGuard::install(store)
}

/// A temporary data root holding a saved testnet profile, its audit key, and
/// the signer identity record, all in the headless keyring the child reads.
///
/// The headless store is this process's default store while the home lives,
/// and the previous default store returns when it drops. Fields drop in
/// declaration order, so the store guard restores the previous store before
/// the temporary home is removed.
struct HeadlessHome {
    _store: DefaultStoreGuard,
    home: tempfile::TempDir,
    profile: Profile,
}

impl HeadlessHome {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let store = install_headless_store(home.path());
        let profile =
            Profile::builder_testnet(SIGNER_SERVICE, SIGNER_ACCOUNT, "halt-e2e-nonce", "default")
                .with_profile_name(PROFILE)
                // The signing call must fail at the seed read, after the audit
                // writer is cached, so this endpoint is never contacted.
                .rpc_url("http://127.0.0.1:9")
                .audit_log_path(home.path().join("audit").join(format!("{PROFILE}.jsonl")))
                .with_noop_engine()
                .build();
        let audit_key = &profile.audit_log_hash_chain_key_id;
        keyring_core::Entry::new(&audit_key.service, &audit_key.account)
            .unwrap()
            .set_password(&URL_SAFE_NO_PAD.encode(AUDIT_KEY))
            .unwrap();
        crate::common::store_named_signer_identity(
            PROFILE,
            SIGNER_SERVICE,
            SIGNER_ACCOUNT,
            [0x48; 32],
        );
        loader::save_to_dir(PROFILE, &profile, &home.path().join("profiles")).unwrap();
        Self {
            _store: store,
            home,
            profile,
        }
    }

    /// The binary bound to this home and the headless keyring.
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_stellar-agent-mcp"));
        command
            .args(["--profile", PROFILE])
            .env("STELLAR_AGENT_HOME", self.home.path())
            .env("STELLAR_AGENT_LOG", "info")
            .env_remove("RUST_LOG")
            .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
            .env(
                "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
                URL_SAFE_NO_PAD.encode(HEADLESS_KEY),
            )
            // Ambient overlays must not select another profile, endpoint, or
            // signer; the persisted profile is what this test exercises.
            .env_remove("STELLAR_AGENT_PROFILE")
            .env_remove("STELLAR_AGENT_CHAIN_ID")
            .env_remove("STELLAR_AGENT_RPC_URL")
            .env_remove("STELLAR_AGENT_SECONDARY_RPC_URL")
            .env_remove("STELLAR_AGENT_ORACLE_PROVIDER_URL")
            .env_remove("STELLAR_AGENT_MCP_SIGNER_DEFAULT")
            .env_remove(OUTBOX_LOCK_WAIT_ENV);
        command
    }

    /// Writes the halt marker and queues its audit row in the outbox, as
    /// `profile halt` does while the server holds the draining writer.
    fn queue_halt_row(&self) -> HaltMarker {
        let marker = HaltMarker::new(
            "2026-10-31T12:00:00Z".to_owned(),
            Some("queued while the server held the writer".to_owned()),
        )
        .unwrap();
        halt::write_halt(self.home.path(), PROFILE, &marker).unwrap();
        AuditOutbox::for_log(
            &self.profile.audit_log_path,
            KeyringTipAnchorStore::shared(
                &self.profile.audit_log_hash_chain_key_id,
                &self.profile.audit_log_path,
            ),
        )
        .append(&AuditEntry::new_profile_halted(
            PROFILE,
            marker.halted_at.as_str(),
            marker.reason.as_deref(),
            "shutdown-drain-test",
        ))
        .unwrap();
        marker
    }

    /// The outbox lock beside the profile's audit log.
    fn outbox_lock(&self) -> std::path::PathBuf {
        std::path::PathBuf::from(format!(
            "{}.outbox.lock",
            self.profile.audit_log_path.display()
        ))
    }

    /// The bytes of the profile's outbox.
    #[cfg(unix)]
    fn outbox_bytes(&self) -> Vec<u8> {
        std::fs::read(stellar_agent_core::audit_log::outbox::outbox_path(
            &self.profile.audit_log_path,
        ))
        .unwrap()
    }
}

/// The number of rows queued in the outbox beside `log_path`.
fn outbox_pending(log_path: &Path) -> usize {
    inspect_outbox(log_path).unwrap().pending
}

/// Asserts the drained `profile_halted` row is in the log.
fn assert_halt_row_in_log(log_path: &Path, marker: &HaltMarker) {
    let content =
        std::fs::read_to_string(log_path).expect("the drained log exists after the server exits");
    let row = content
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|row| row["kind"] == "profile_halted")
        .unwrap_or_else(|| panic!("the drained halt row is in the log: {content}"));
    assert_eq!(row["halted_at"], marker.halted_at.as_str());
    assert_eq!(row["reason"], marker.reason.as_deref().unwrap());
}

/// Spawns `command` under the shared driver and completes the MCP
/// initialization handshake.
fn start_server(command: Command) -> ChildDriver {
    handshake(ChildDriver::spawn(command))
}

/// Completes the MCP initialization handshake with a spawned server.
fn handshake(mut server: ChildDriver) -> ChildDriver {
    let init = server.request(
        "initialize",
        &json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "halt-integration", "version": "0" },
        }),
    );
    assert!(init.get("result").is_some(), "initialize failed: {init}");
    server.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
    server
}

/// Opens the server's keyed audit writer by making a signing call that fails
/// at the seed read, then queues a halt row and closes stdin. The server must
/// drain the row before it exits, with no keyed command run after it.
#[test]
#[serial]
fn the_server_drains_a_queued_halt_row_when_its_stdin_closes() {
    let fixture = HeadlessHome::new();
    let mut server = start_server(fixture.command());
    let response = server.call("stellar_sep43_sign_message", &sign_message_args());
    assert_eq!(
        envelope_code(&response).as_deref(),
        Some("sep43.wallet_unlock_failed"),
        "the signing call reaches the missing seed after the audit pre-flight: {response}"
    );
    assert!(
        fixture.profile.audit_log_path.is_file(),
        "the call opened and cached the keyed audit writer"
    );

    let marker = fixture.queue_halt_row();
    assert_eq!(
        outbox_pending(&fixture.profile.audit_log_path),
        1,
        "the halt row is queued while the server holds the writer"
    );

    server.close_stdin();
    let (status, stderr) = server.wait();
    assert!(
        status.success(),
        "the server exits cleanly at EOF.\nstderr: {stderr}"
    );
    assert_eq!(
        outbox_pending(&fixture.profile.audit_log_path),
        0,
        "the server drains the queued halt row at exit.\nstderr: {stderr}"
    );
    assert_halt_row_in_log(&fixture.profile.audit_log_path, &marker);
}

/// The same contract for SIGTERM: the server handles the signal, drains the
/// queued row, and exits `0`.
#[cfg(unix)]
#[test]
#[serial]
fn the_server_drains_a_queued_halt_row_on_sigterm() {
    let fixture = HeadlessHome::new();
    let mut server = start_server(fixture.command());
    let response = server.call("stellar_sep43_sign_message", &sign_message_args());
    assert_eq!(
        envelope_code(&response).as_deref(),
        Some("sep43.wallet_unlock_failed"),
        "the signing call reaches the missing seed after the audit pre-flight: {response}"
    );
    assert!(
        fixture.profile.audit_log_path.is_file(),
        "the call opened and cached the keyed audit writer"
    );

    let marker = fixture.queue_halt_row();
    assert_eq!(
        outbox_pending(&fixture.profile.audit_log_path),
        1,
        "the halt row is queued while the server holds the writer"
    );

    // `kill` is a shell builtin, so this needs no procps installation.
    let delivered = Command::new("sh")
        .arg("-c")
        .arg(format!("kill -TERM {}", server.id()))
        .status()
        .expect("sh must run");
    assert!(delivered.success(), "SIGTERM must be delivered");

    let (status, stderr) = server.wait();
    assert!(
        status.success(),
        "the server exits cleanly on SIGTERM.\nstderr: {stderr}"
    );
    assert_eq!(
        outbox_pending(&fixture.profile.audit_log_path),
        0,
        "the server drains the queued halt row on SIGTERM.\nstderr: {stderr}"
    );
    assert_halt_row_in_log(&fixture.profile.audit_log_path, &marker);
}

/// The child reads the credentials the fixture stores in this process: the
/// headless dependency's `test-helpers` feature makes it resolve the store
/// file under `STELLAR_AGENT_HOME`. The headless store is this process's
/// default only while the fixture lives, and the parent's store returns after.
#[test]
#[serial]
fn halt_fixture_shares_the_home_with_the_child_and_restores_the_parent_store() {
    let parent: Arc<keyring_core::CredentialStore> = keyring_core::mock::Store::new().unwrap();
    let _parent = DefaultStoreGuard::install(Arc::clone(&parent));
    keyring_core::Entry::new("halt-parent-svc", "halt-parent-user")
        .unwrap()
        .set_password("parent")
        .unwrap();
    let is_parent = |store: Option<Arc<keyring_core::CredentialStore>>| {
        store.is_some_and(|store| Arc::ptr_eq(&store, &parent))
    };

    {
        let fixture = HeadlessHome::new();
        assert!(
            !is_parent(keyring_core::get_default_store()),
            "the headless store is the default while the fixture lives"
        );
        assert!(
            headless_store_path(fixture.home.path()).is_file(),
            "the fixture's credentials are in the store file under the home"
        );

        let mut server = start_server(fixture.command());
        let response = server.call("stellar_sep43_sign_message", &sign_message_args());
        assert_eq!(
            envelope_code(&response).as_deref(),
            Some("sep43.wallet_unlock_failed"),
            "the child reads the audit key the fixture stored and reaches the seed read: \
             {response}"
        );
        assert!(
            !is_parent(keyring_core::get_default_store()),
            "the fixture keeps its store installed while the child runs"
        );
        server.close_stdin();
        let (status, stderr) = server.wait();
        assert!(status.success(), "{stderr}");
    }

    assert!(
        is_parent(keyring_core::get_default_store()),
        "dropping the fixture restores the parent's store"
    );
    assert_eq!(
        keyring_core::Entry::new("halt-parent-svc", "halt-parent-user")
            .unwrap()
            .get_password()
            .unwrap(),
        "parent",
        "the restored store keeps its credential"
    );
}

/// The exit code of a second shutdown event during the shutdown wait or the
/// exit drain.
#[cfg(unix)]
const EXIT_SECOND_SIGNAL: i32 = 3;

/// Every ordered pair of the two Unix shutdown signals.
#[cfg(unix)]
const SIGNAL_PAIRS: [(&str, &str); 4] = [
    ("INT", "INT"),
    ("INT", "TERM"),
    ("TERM", "INT"),
    ("TERM", "TERM"),
];

/// The event the transport logs when a shutdown reaches a running session,
/// right before the shutdown wait starts.
#[cfg(target_os = "linux")]
const STOPPING_EVENT: &str = "stellar-agent-mcp: shutdown signal received; stopping the MCP server";

/// The warning that ends a shutdown wait the session outlasted.
#[cfg(target_os = "linux")]
const SHUTDOWN_WAIT_ENDED: &str = "did not stop within the shutdown wait";

/// The event the server logs after the exit drain returns.
const DRAIN_FINISHED: &str = "drained cached audit outboxes at exit";

/// The debug event a drain emits when it starts to wait on a held outbox lock.
const OUTBOX_WAIT_EVENT: &str = "audit outbox: the outbox lock is held; waiting for it";

/// The outbox lock wait of a server child whose drain the test holds on the
/// outbox lock.
const HELD_LOCK_WAIT: Duration = Duration::from_secs(60);

/// The log filter that adds the outbox's debug events to the info level.
const OUTBOX_DEBUG_LOG: &str = "info,stellar_agent_core::audit_log::outbox=debug";

/// How long a binary test waits for an event the child logs.
const EVENT_DEADLINE: Duration = Duration::from_secs(30);

/// Sends `SIG<signal>` to `pid` through the shell's `kill` builtin.
#[cfg(unix)]
fn send_signal(pid: u32, signal: &str) {
    let delivered = Command::new("sh")
        .arg("-c")
        .arg(format!("kill -{signal} {pid}"))
        .status()
        .expect("sh must run");
    assert!(delivered.success(), "SIG{signal} must be delivered");
}

/// A second signal during the shutdown wait ends the process with exit code
/// 3 while the session still cannot stop.
///
/// The test stops reading the server's stdout and requests enough tool lists
/// to fill the pipe, so a response write blocks and the session cannot stop on
/// cancel. It observes the full pipe, sends the first signal, waits for the
/// transport's stopping event, and sends the second. The process exits before
/// the shutdown wait ends, while the pipe is still full and unread, and runs
/// no drain.
#[cfg(target_os = "linux")]
#[test]
#[serial]
fn second_signal_exits_during_shutdown_wait() {
    for (first, second) in SIGNAL_PAIRS {
        let fixture = HeadlessHome::new();
        let mut server = start_server(fixture.command());
        let list = server.request("tools/list", &json!({}));
        let list_bytes = serde_json::to_string(&list).unwrap().len();
        // Four times the largest pipe Linux allows, so a write blocks whatever
        // the pipe's size.
        let requests = (4 * (1 << 20) / list_bytes).max(2);

        server.pause_stdout();
        for index in 0..requests {
            server.send(&json!({
                "jsonrpc": "2.0",
                "id": 10_000 + index,
                "method": "tools/list",
                "params": {}
            }));
        }
        let deadline = Instant::now() + EVENT_DEADLINE;
        while !server.stdout_pipe_is_full() {
            assert!(
                Instant::now() < deadline,
                "SIG{first}, SIG{second}: the server fills its stdout pipe.\nstderr: {}",
                server.stderr()
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        send_signal(server.id(), first);
        server.wait_for_stderr(STOPPING_EVENT, EVENT_DEADLINE);
        let signalled_at = Instant::now();
        send_signal(server.id(), second);
        let status = server.wait_for_exit(SHUTDOWN_WAIT + EVENT_DEADLINE);
        let elapsed = signalled_at.elapsed();
        let blocker_held = server.stdout_is_paused() && server.stdout_pipe_is_full();
        let stderr = server.stderr();

        let status = status.unwrap_or_else(|| {
            panic!("SIG{first}, SIG{second}: the server exits.\nstderr: {stderr}")
        });
        assert_eq!(
            status.code(),
            Some(EXIT_SECOND_SIGNAL),
            "SIG{first}, SIG{second}: the second signal exits with code 3.\nstderr: {stderr}"
        );
        assert!(
            elapsed < SHUTDOWN_WAIT,
            "SIG{first}, SIG{second}: the process ends before the shutdown wait does: \
             {elapsed:?}"
        );
        assert!(
            blocker_held,
            "SIG{first}, SIG{second}: the unread stdout pipe still blocks the session at exit"
        );
        assert!(
            !stderr.contains(SHUTDOWN_WAIT_ENDED) && !stderr.contains(DRAIN_FINISHED),
            "SIG{first}, SIG{second}: neither the shutdown wait nor the drain completes.\n\
             stderr: {stderr}"
        );
        server.resume_stdout();
    }
}

/// A second signal during the exit drain ends the process with exit code 3,
/// leaves the queued row and the outbox unchanged, and a restarted server
/// delivers the row.
///
/// The test holds the outbox lock, so the drain the first signal starts waits
/// on it. The drain's wait event shows the drain has started; the second
/// signal then ends the process long before that wait would.
#[cfg(unix)]
#[test]
#[serial]
fn second_signal_exits_during_exit_drain() {
    for (first, second) in SIGNAL_PAIRS {
        let fixture = HeadlessHome::new();
        let mut command = fixture.command();
        command
            .env(OUTBOX_LOCK_WAIT_ENV, HELD_LOCK_WAIT.as_millis().to_string())
            .env("STELLAR_AGENT_LOG", OUTBOX_DEBUG_LOG);
        let mut server = start_server(command);
        let response = server.call("stellar_sep43_sign_message", &sign_message_args());
        assert_eq!(
            envelope_code(&response).as_deref(),
            Some("sep43.wallet_unlock_failed"),
            "the signing call caches the keyed audit writer: {response}"
        );
        let marker = fixture.queue_halt_row();
        assert_eq!(outbox_pending(&fixture.profile.audit_log_path), 1);
        let queued = fixture.outbox_bytes();
        let log_before = std::fs::read(&fixture.profile.audit_log_path).unwrap();

        let lock =
            stellar_agent_core::audit_log::test_helpers::hold_audit_lock(&fixture.outbox_lock())
                .unwrap();
        send_signal(server.id(), first);
        server.wait_for_stderr(OUTBOX_WAIT_EVENT, EVENT_DEADLINE);
        let signalled_at = Instant::now();
        send_signal(server.id(), second);
        let status = server.wait_for_exit(EVENT_DEADLINE);
        let elapsed = signalled_at.elapsed();
        let stderr = server.stderr();
        drop(server);

        let status = status.unwrap_or_else(|| {
            panic!("SIG{first}, SIG{second}: the server exits.\nstderr: {stderr}")
        });
        assert_eq!(
            status.code(),
            Some(EXIT_SECOND_SIGNAL),
            "SIG{first}, SIG{second}: the second signal exits with code 3.\nstderr: {stderr}"
        );
        assert!(
            elapsed < HELD_LOCK_WAIT,
            "SIG{first}, SIG{second}: the process ends before the drain's lock wait: \
             {elapsed:?}"
        );
        assert!(
            !stderr.contains(DRAIN_FINISHED),
            "SIG{first}, SIG{second}: the drain does not complete.\nstderr: {stderr}"
        );
        assert_eq!(
            outbox_pending(&fixture.profile.audit_log_path),
            1,
            "SIG{first}, SIG{second}: the row stays queued"
        );
        assert_eq!(
            fixture.outbox_bytes(),
            queued,
            "SIG{first}, SIG{second}: the outbox is unchanged"
        );
        assert_eq!(
            std::fs::read(&fixture.profile.audit_log_path).unwrap(),
            log_before,
            "SIG{first}, SIG{second}: the log is unchanged"
        );

        // The marker is lifted so the restarted server's signing call reaches
        // the keyed writer, whose acquisition drains the outbox. Lifting the
        // marker leaves the outbox untouched.
        drop(lock);
        assert!(halt::clear_halt(fixture.home.path(), PROFILE).unwrap());
        assert_eq!(fixture.outbox_bytes(), queued);
        let mut restarted = start_server(fixture.command());
        let response = restarted.call("stellar_sep43_sign_message", &sign_message_args());
        assert_eq!(
            envelope_code(&response).as_deref(),
            Some("sep43.wallet_unlock_failed"),
            "the restarted server's keyed writer drains the outbox: {response}"
        );
        restarted.close_stdin();
        let (status, stderr) = restarted.wait();
        assert!(status.success(), "{stderr}");
        assert_eq!(
            outbox_pending(&fixture.profile.audit_log_path),
            0,
            "SIG{first}, SIG{second}: the restarted server delivers the row.\nstderr: {stderr}"
        );
        assert_halt_row_in_log(&fixture.profile.audit_log_path, &marker);
    }
}

/// The source of the binary, whose listeners the Windows tests count.
#[cfg(windows)]
const MAIN_SOURCE: &str = include_str!("../../src/main.rs");

/// The variable that makes the named listener registrations fail in a binary
/// built with `test-helpers`.
#[cfg(windows)]
const LISTENER_FAILURE_ENV: &str = "STELLAR_AGENT_TEST_SHUTDOWN_LISTENER_FAILURE";

/// The event the server logs when its supervisor receives the first shutdown
/// event.
#[cfg(windows)]
const SHUTDOWN_EVENT: &str = "stellar-agent-mcp: shutdown event received";

/// Real console events for a server child that a pseudoconsole hosts.
///
/// The driver starts the child as the client of a pseudoconsole of its own,
/// in a new process group. Ctrl-Break goes to that process group through
/// `GenerateConsoleCtrlEvent` from inside the child's console. The console
/// close is `ClosePseudoConsole`, which sends `CTRL_CLOSE_EVENT` to every
/// connected client. The test process is not attached to the pseudoconsole
/// when it closes, so the event reaches only the child.
#[cfg(windows)]
mod windows_console {
    #![allow(unsafe_code, reason = "console API calls the tests make on a child")]

    const CTRL_BREAK_EVENT: u32 = 1;
    const ATTACH_PARENT_PROCESS: u32 = u32::MAX;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn FreeConsole() -> i32;
        fn AttachConsole(process_id: u32) -> i32;
        fn GenerateConsoleCtrlEvent(ctrl_event: u32, process_group_id: u32) -> i32;
        fn GetLastError() -> u32;
    }

    /// Runs `f` attached to the console of `pid`, then returns this process
    /// to its parent's console when it has one.
    fn attached_to<T>(pid: u32, f: impl FnOnce() -> T) -> T {
        // SAFETY: FreeConsole and AttachConsole take no pointers. Detaching
        // first is required: a process attaches to one console at a time.
        let attached = unsafe {
            FreeConsole();
            AttachConsole(pid)
        };
        // SAFETY: GetLastError reads this thread's last error value.
        let error = unsafe { GetLastError() };
        assert_ne!(
            attached, 0,
            "the test attaches to the child's console (error {error})"
        );
        let result = f();
        // SAFETY: as above; a failure to reattach leaves the test without a
        // console, which its piped output does not need.
        unsafe {
            FreeConsole();
            AttachConsole(ATTACH_PARENT_PROCESS);
        }
        result
    }

    /// Sends a Ctrl-Break to the process group of `pid` and reports whether
    /// Windows accepts it. A failure leaves the test's console state as
    /// `attached_to` leaves it, and nothing panics.
    pub fn interrupt(pid: u32) -> bool {
        // SAFETY: as in `attached_to` and `send_ctrl_break`; no call takes a
        // pointer.
        unsafe {
            FreeConsole();
            let sent =
                AttachConsole(pid) != 0 && GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) != 0;
            FreeConsole();
            AttachConsole(ATTACH_PARENT_PROCESS);
            sent
        }
    }

    /// Sends a real Ctrl-Break to the process group of `pid`.
    pub fn send_ctrl_break(pid: u32) {
        let sent = attached_to(pid, || {
            // SAFETY: the call takes no pointers; the group id is the child's
            // process id because the child leads a new process group.
            unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) }
        });
        assert_ne!(sent, 0, "Ctrl-Break is delivered to the child's group");
    }
}

/// Starts a Windows server child in a pseudoconsole of its own, caches its
/// keyed writer with a signing call, and queues a halt row while the server
/// holds it.
#[cfg(windows)]
fn windows_server_with_a_queued_row(
    fixture: &HeadlessHome,
    listener_failure: Option<&str>,
) -> (ChildDriver, HaltMarker) {
    let mut command = fixture.command();
    // A drain the test holds on the outbox lock waits long enough to observe,
    // and logs when its wait starts. JSON logs keep the level checks valid
    // whatever format the parent environment selects.
    command
        .env(OUTBOX_LOCK_WAIT_ENV, HELD_LOCK_WAIT.as_millis().to_string())
        .env("STELLAR_AGENT_LOG", OUTBOX_DEBUG_LOG)
        .env("STELLAR_AGENT_LOG_FORMAT", "json");
    if let Some(failing) = listener_failure {
        command.env(LISTENER_FAILURE_ENV, failing);
    }
    let server = ChildDriver::spawn_in_pseudo_console(command)
        .unwrap_or_else(|error| panic!("the server starts in a pseudoconsole: {error}"));
    // The handshake completes before any close, so the close never meets a
    // client that is still starting.
    let mut server = handshake(server);
    let response = server.call("stellar_sep43_sign_message", &sign_message_args());
    assert_eq!(
        envelope_code(&response).as_deref(),
        Some("sep43.wallet_unlock_failed"),
        "the signing call caches the keyed audit writer: {response}"
    );
    let marker = fixture.queue_halt_row();
    assert_eq!(outbox_pending(&fixture.profile.audit_log_path), 1);
    (server, marker)
}

/// Closes the pseudoconsole of `server` and waits for its shutdown event.
///
/// The failure text reports what the wait observes. It names the expected
/// text and the elapsed wait, whether the child runs or has an exit status,
/// its stderr pipe state, and the captured stderr. The event line passes. A child
/// that still runs at the deadline gets a Ctrl-Break and a bounded exit wait
/// before the failure.
#[cfg(windows)]
fn close_console_and_await_delivery(server: &mut ChildDriver) {
    let close_started = server.close_pseudo_console();
    let started = Instant::now();
    let outcome = server.await_stderr(SHUTDOWN_EVENT, EVENT_DEADLINE);
    let elapsed = started.elapsed();
    match outcome {
        StderrWait::Shown(_) => {}
        StderrWait::Exited { status, stderr } => panic!(
            "expected {SHUTDOWN_EVENT:?} after the pseudoconsole close (started: \
             {close_started}); after {elapsed:?} the child's exit status is {status} and its \
             stderr pipe is closed.\nstderr: {stderr}"
        ),
        StderrWait::ExitedWithOpenStderr { status, stderr } => panic!(
            "expected {SHUTDOWN_EVENT:?} after the pseudoconsole close (started: \
             {close_started}); after {elapsed:?} the child's exit status is {status} and its \
             stderr pipe is open.\nstderr so far: {stderr}"
        ),
        StderrWait::Running(stderr) => {
            let interrupted = windows_console::interrupt(server.id());
            let status = server.wait_for_exit(EXIT_DEADLINE);
            panic!(
                "expected {SHUTDOWN_EVENT:?} after the pseudoconsole close (started: \
                 {close_started}); after {elapsed:?} the child runs. Ctrl-Break send: \
                 {interrupted}; exit status within {EXIT_DEADLINE:?} of it: {status:?}.\n\
                 stderr: {stderr}"
            )
        }
    }
}

/// Waits for the server to log `event_name` as its first shutdown event,
/// releases `held_outbox`, and waits for the exit. Asserts exit code `0` and
/// the drained row.
#[cfg(windows)]
fn assert_event_drains(
    fixture: &HeadlessHome,
    mut server: ChildDriver,
    marker: &HaltMarker,
    event_name: &str,
    held_outbox: Option<stellar_agent_core::audit_log::test_helpers::HeldAuditLock>,
) {
    let observed = server.wait_for_stderr(SHUTDOWN_EVENT, EVENT_DEADLINE);
    let delivered = observed
        .lines()
        .find(|line| line.contains(SHUTDOWN_EVENT))
        .unwrap_or_default()
        .to_owned();
    assert!(
        delivered.contains(event_name),
        "the server received {event_name}: {delivered}"
    );
    drop(held_outbox);
    let (status, stderr) = server.wait();
    assert_eq!(
        status.code(),
        Some(0),
        "the server exits cleanly on {event_name}.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains(DRAIN_FINISHED),
        "the drain finishes before the process ends.\nstderr: {stderr}"
    );
    assert_eq!(
        outbox_pending(&fixture.profile.audit_log_path),
        0,
        "the server drains the queued halt row on {event_name}.\nstderr: {stderr}"
    );
    assert_halt_row_in_log(&fixture.profile.audit_log_path, marker);
}

/// A real Ctrl-Break reaches a server in its own console, which drains the
/// queued halt row and exits `0`.
#[cfg(windows)]
#[test]
#[serial]
fn windows_ctrl_break_drains_a_queued_halt_row() {
    assert_eq!(
        MAIN_SOURCE
            .matches("tokio::signal::windows::ctrl_break()")
            .count(),
        1,
        "one Ctrl-Break listener is registered"
    );
    let fixture = HeadlessHome::new();
    let (server, marker) = windows_server_with_a_queued_row(&fixture, None);
    windows_console::send_ctrl_break(server.id());
    assert_event_drains(&fixture, server, &marker, "ctrl-break", None);
}

/// Closing the console of a server in its own console delivers a real close
/// event, and the server drains the queued halt row before the process ends.
#[cfg(windows)]
#[test]
#[serial]
fn windows_console_close_drains_a_queued_halt_row() {
    assert_eq!(
        MAIN_SOURCE
            .matches("tokio::signal::windows::ctrl_close()")
            .count(),
        1,
        "one console close listener is registered"
    );
    let fixture = HeadlessHome::new();
    let (mut server, marker) = windows_server_with_a_queued_row(&fixture, None);
    close_console_and_await_delivery(&mut server);
    assert_event_drains(&fixture, server, &marker, "ctrl-close", None);
}

/// A listener whose registration fails logs a `WARN` event and does not shut
/// the server down, and the other Windows listener still drains on its event.
///
/// The test closes stdin first and holds the drain on the outbox lock. The
/// event that follows EOF is the first shutdown event, so the process exits
/// `0` once the lock is released, not with the second-event code.
#[cfg(windows)]
#[test]
#[serial]
fn windows_listener_registration_failure_warns_and_keeps_other_listeners_active() {
    for (failing, warning, delivered) in [
        (
            "ctrl-break",
            "stellar-agent-mcp: cannot listen for Ctrl-Break",
            "ctrl-close",
        ),
        (
            "ctrl-close",
            "stellar-agent-mcp: cannot listen for console close",
            "ctrl-break",
        ),
    ] {
        let fixture = HeadlessHome::new();
        let (mut server, marker) = windows_server_with_a_queued_row(&fixture, Some(failing));
        let stderr = server.wait_for_stderr(warning, EVENT_DEADLINE);
        let warning_line = stderr
            .lines()
            .find(|line| line.contains(warning))
            .unwrap_or_default();
        assert!(
            warning_line.contains("\"level\":\"WARN\""),
            "the failed {failing} registration logs at WARN: {warning_line}"
        );
        assert!(
            !stderr.contains(SHUTDOWN_EVENT),
            "a failed {failing} registration starts no shutdown.\nstderr: {stderr}"
        );
        let ping = server.request("ping", &json!({}));
        assert!(
            ping.get("result").is_some(),
            "the server keeps serving after the failed {failing} registration: {ping}"
        );

        let held =
            stellar_agent_core::audit_log::test_helpers::hold_audit_lock(&fixture.outbox_lock())
                .unwrap();
        server.close_stdin();
        server.wait_for_stderr(OUTBOX_WAIT_EVENT, EVENT_DEADLINE);
        if delivered == "ctrl-break" {
            windows_console::send_ctrl_break(server.id());
        } else {
            close_console_and_await_delivery(&mut server);
        }
        assert_event_drains(&fixture, server, &marker, delivered, Some(held));
    }
}
