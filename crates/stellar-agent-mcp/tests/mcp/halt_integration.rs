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
//! Two tests drive the real binary over stdio. They queue a `profile_halted`
//! row in the audit outbox while the server holds the keyed writer, then close
//! stdin or send SIGTERM, and assert the server drains the row into the log
//! before it exits.
//!
//! Two more tests drive `serve_on_until` over a duplex stream: a shutdown
//! future stops a live session, and the shutdown wait bounds a session that
//! cannot stop.
//!
//! The tools under test come from the server's own descriptors, so a tool
//! added later is covered without editing this file.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in integration tests"
)]

use std::io::{BufRead as _, Write as _};
use std::path::Path;
use std::process::{Child, Command, Stdio};
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
use stellar_agent_test_support::{StellarAgentHomeGuard, keyring_mock};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};

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

// ── The binary's exit drain ──────────────────────────────────────────────────

/// The key that seals the headless store the test process and the server child
/// share.
const HEADLESS_KEY: [u8; 32] = [0x6d; 32];

/// Installs the file-backed keyring store at the path the child resolves from
/// `STELLAR_AGENT_HOME`, and makes it this process's default store.
fn install_headless_store(home: &Path) {
    let store: Arc<keyring_core::CredentialStore> =
        Arc::new(stellar_agent_headless_keyring::store::HeadlessStore::new(
            home.join("headless-keyring").join("store.keyring"),
            stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                zeroize::Zeroizing::new(HEADLESS_KEY),
            )),
        ));
    keyring_core::set_default_store(store);
}

/// A temporary data root with a saved testnet profile, its audit key, and the
/// signer identity record, all in the headless keyring the child will read.
struct HeadlessServer {
    home: tempfile::TempDir,
    profile: Profile,
}

impl HeadlessServer {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        install_headless_store(home.path());
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
        Self { home, profile }
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

/// A server child driven over its real stdio pipes.
struct ChildServer {
    child: Child,
    stdin: Option<std::io::BufWriter<std::process::ChildStdin>>,
    stdout: std::io::BufReader<std::process::ChildStdout>,
    stderr: Option<std::process::ChildStderr>,
    next_id: u64,
}

impl ChildServer {
    fn start(mut command: Command) -> Self {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("stellar-agent-mcp binary must spawn");
        let stdin = std::io::BufWriter::new(child.stdin.take().expect("child stdin must be piped"));
        let stdout =
            std::io::BufReader::new(child.stdout.take().expect("child stdout must be piped"));
        let stderr = child.stderr.take();
        let mut server = Self {
            child,
            stdin: Some(stdin),
            stdout,
            stderr,
            next_id: 1,
        };
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

    fn send(&mut self, message: &Value) {
        let line = serde_json::to_string(message).unwrap();
        let stdin = self.stdin.as_mut().expect("child stdin is open");
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
    }

    /// Sends one request and returns its response, skipping notifications.
    fn request(&mut self, method: &str, params: &Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        loop {
            let mut line = String::new();
            let read = self
                .stdout
                .read_line(&mut line)
                .expect("child stdout must be readable");
            assert!(
                read > 0,
                "the server closed stdout before answering {method}"
            );
            let message: Value = serde_json::from_str(&line).unwrap();
            if message["id"] == json!(id) {
                return message;
            }
        }
    }

    fn call(&mut self, tool: &str, arguments: &Value) -> Value {
        self.request(
            "tools/call",
            &json!({ "name": tool, "arguments": arguments }),
        )
    }

    /// Closes the child's stdin, which ends the stdio session at EOF.
    fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// Waits for the child to exit and returns its status and stderr.
    fn wait(mut self) -> (std::process::ExitStatus, String) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                let mut stderr = String::new();
                if let Some(mut pipe) = self.stderr.take() {
                    use std::io::Read as _;
                    pipe.read_to_string(&mut stderr).unwrap();
                }
                return (status, stderr);
            }
            if std::time::Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                let mut stderr = String::new();
                if let Some(mut pipe) = self.stderr.take() {
                    use std::io::Read as _;
                    let _ = pipe.read_to_string(&mut stderr);
                }
                panic!("the MCP server did not exit within 30 seconds.\nstderr: {stderr}");
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }
}

/// Opens the server's keyed audit writer by making a signing call that fails
/// at the seed read, then queues a halt row and closes stdin. The server must
/// drain the row before it exits, with no keyed command run after it.
#[test]
#[serial]
fn the_server_drains_a_queued_halt_row_when_its_stdin_closes() {
    let fixture = HeadlessServer::new();
    let mut server = ChildServer::start(fixture.command());
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
    let fixture = HeadlessServer::new();
    let mut server = ChildServer::start(fixture.command());
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
        .arg(format!("kill -TERM {}", server.child.id()))
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
