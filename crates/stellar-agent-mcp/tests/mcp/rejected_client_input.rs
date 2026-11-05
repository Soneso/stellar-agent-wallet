//! Rejected client input stays out of the MCP envelopes, the returned errors
//! and the log at the most verbose directive, over an in-memory transport and
//! at the binary's final startup log.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in integration tests"
)]

use std::io::Write as _;
use std::pin::Pin;
use std::process::Stdio;
use std::task::{Context, Poll};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use stellar_agent_core::observability::{FormatChoice, SubscriberConfig, subscriber_for_tests};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::STELLAR_AGENT_MCP_MAX_LINE_BYTES;
use stellar_agent_mcp::server::WalletServer;
use stellar_agent_mcp::transport::{BoundedTransport, SessionStartError, serve_on};
use stellar_agent_test_support::CaptureWriter;
use stellar_agent_test_support::log_capture::inert_dispatcher;
use tokio::io::{AsyncBufReadExt as _, AsyncRead, AsyncWriteExt as _, BufReader, ReadBuf};

const MARKER: &str = "credmarker7";

fn testnet_server() -> WalletServer {
    WalletServer::new(
        Profile::builder_testnet_named("rejected-input", "s", "a", "n", "a")
            .with_noop_engine()
            .build(),
    )
    .expect("server builds")
}

/// A capture of the wallet's subscriber stack at the most verbose directive,
/// active on this thread until the returned guards drop.
struct TraceCapture {
    writer: CaptureWriter,
    _default: tracing::dispatcher::DefaultGuard,
    _inert: tracing::Dispatch,
}

impl TraceCapture {
    fn start(format: FormatChoice) -> Self {
        let writer = CaptureWriter::new();
        let sink = writer.clone();
        let inert = inert_dispatcher();
        let subscriber = subscriber_for_tests(
            SubscriberConfig::default()
                .with_filter_override(Some(tracing_subscriber::EnvFilter::new("trace")))
                .with_format_override(Some(format))
                .with_writer_factory(Some(Box::new(move || Box::new(sink.clone())))),
        )
        .expect("the wallet subscriber builds");
        let default = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        Self {
            writer,
            _default: default,
            _inert: inert,
        }
    }

    fn logs(&self) -> String {
        self.writer.captured_str()
    }
}

/// Serves `frames` to a fresh server and returns the outcome of the session.
async fn serve_frames(frames: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let (client, server_side) = tokio::io::duplex(4 << 20);
    let (server_read, server_write) = tokio::io::split(server_side);
    let (_client_read, mut client_write) = tokio::io::split(client);
    client_write.write_all(frames).await.unwrap();
    client_write.shutdown().await.unwrap();
    serve_on(
        testnet_server(),
        BoundedTransport::over(server_read, server_write),
    )
    .await
}

fn frame(message: &Value) -> Vec<u8> {
    let mut line = serde_json::to_vec(message).unwrap();
    line.push(b'\n');
    line
}

fn initialize(protocol_version: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": protocol_version,
            "capabilities": {},
            "clientInfo": { "name": "rejected-input", "version": "0" },
        },
    })
}

/// A request before `initialize` is refused with the fixed text, and neither
/// the error's forms nor its source chain hold the message.
#[tokio::test(flavor = "current_thread")]
async fn a_request_before_initialize_is_refused_without_its_payload() {
    let capture = TraceCapture::start(FormatChoice::Pretty);
    let error = serve_frames(&frame(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": { "cursor": MARKER },
    })))
    .await
    .expect_err("the session refuses");

    assert_eq!(
        error.to_string(),
        "the MCP client must open the session with an initialize request"
    );
    assert_eq!(
        error.downcast_ref::<SessionStartError>(),
        Some(&SessionStartError::ExpectedInitializeRequest)
    );
    assert!(!format!("{error:?}").contains(MARKER), "{error:?}");
    assert!(error.source().is_none());
    let logs = capture.logs();
    assert!(!logs.contains(MARKER), "{logs}");
}

/// A frame of malformed typed JSON ends the session with an event that holds
/// its position alone.
#[tokio::test(flavor = "current_thread")]
async fn a_malformed_frame_logs_its_position_alone() {
    for format in [FormatChoice::Pretty, FormatChoice::Json] {
        let capture = TraceCapture::start(format);
        let error = serve_frames(&frame(&json!({
            "jsonrpc": "2.0",
            "id": { MARKER: true },
            "method": 7,
            "params": MARKER,
        })))
        .await
        .expect_err("the session refuses");

        assert_eq!(
            error.to_string(),
            "the MCP client must stay connected until the session starts"
        );
        let logs = capture.logs();
        assert!(
            logs.contains("the frame is not a valid JSON-RPC message"),
            "{logs}"
        );
        assert!(logs.contains("column"), "{logs}");
        assert!(!logs.contains(MARKER), "{logs}");
    }
}

/// A frame over the line limit ends the session with the fixed event.
#[tokio::test(flavor = "current_thread")]
async fn an_oversized_frame_logs_the_line_limit() {
    let capture = TraceCapture::start(FormatChoice::Pretty);
    let mut line = MARKER.repeat(STELLAR_AGENT_MCP_MAX_LINE_BYTES / MARKER.len() + 2);
    line.push('\n');
    serve_frames(line.as_bytes())
        .await
        .expect_err("the session refuses");

    let logs = capture.logs();
    assert!(logs.contains("the frame exceeds the line limit"), "{logs}");
    assert!(!logs.contains(MARKER), "{logs}");
}

/// A reader that fails with an error whose text holds the marker.
struct FailingReader;

impl AsyncRead for FailingReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Err(std::io::Error::other(MARKER)))
    }
}

/// A read failure ends the session with the fixed event and the I/O kind.
#[tokio::test(flavor = "current_thread")]
async fn a_read_failure_logs_the_io_kind() {
    let capture = TraceCapture::start(FormatChoice::Pretty);
    let (_client, server_side) = tokio::io::duplex(1 << 10);
    let (_unused, server_write) = tokio::io::split(server_side);
    serve_on(
        testnet_server(),
        BoundedTransport::over(FailingReader, server_write),
    )
    .await
    .expect_err("the session refuses");

    let logs = capture.logs();
    assert!(logs.contains("the frame could not be read"), "{logs}");
    assert!(logs.contains("other error"), "{logs}");
    assert!(!logs.contains(MARKER), "{logs}");
}

/// A client's unsupported protocol version and a rejected frame stay out of
/// the log at the most verbose directive, while the wallet and the rest of
/// rmcp keep logging.
#[tokio::test(flavor = "current_thread")]
async fn held_rmcp_events_stay_out_of_a_real_session() {
    let capture = TraceCapture::start(FormatChoice::Pretty);
    let mut frames = frame(&initialize(MARKER));
    frames.extend(frame(
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    ));
    frames.extend_from_slice(format!("{{\"id\": \"{MARKER}\"\n").as_bytes());
    serve_frames(&frames).await.expect("the session ends");

    let logs = capture.logs();
    assert!(logs.contains("MCP server ready"), "{logs}");
    assert!(logs.contains("serve finished"), "{logs}");
    assert!(
        logs.contains("the frame is not a valid JSON-RPC message"),
        "{logs}"
    );
    assert!(!logs.contains(MARKER), "{logs}");
}

/// A rejected tool argument stays out of the log at the most verbose
/// directive, with the session's own events in place.
#[tokio::test(flavor = "current_thread")]
async fn a_rejected_argument_stays_out_of_the_log() {
    let capture = TraceCapture::start(FormatChoice::Pretty);
    let response = tool_response(
        "stellar_balances",
        json!({ "chain_id": "stellar:testnet", "account_id": "G", "assets": MARKER }),
    )
    .await;

    assert_eq!(response["result"]["isError"], true, "{response}");
    let logs = capture.logs();
    assert!(logs.contains("MCP server ready"), "{logs}");
    assert!(!logs.contains(MARKER), "{logs}");
}

/// The tool call response for `name` with `arguments`.
async fn tool_response(name: &str, arguments: Value) -> Value {
    let (client, server_side) = tokio::io::duplex(1 << 20);
    let (server_read, server_write) = tokio::io::split(server_side);
    let session = tokio::spawn(async move {
        let _ = serve_on_send(server_read, server_write).await;
    });
    let (client_read, mut client_write) = tokio::io::split(client);
    let mut lines = BufReader::new(client_read).lines();
    client_write
        .write_all(&frame(&initialize("2024-11-05")))
        .await
        .unwrap();
    lines.next_line().await.unwrap().expect("initialize result");
    client_write
        .write_all(&frame(
            &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        ))
        .await
        .unwrap();
    client_write
        .write_all(&frame(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments },
        })))
        .await
        .unwrap();
    let response = lines.next_line().await.unwrap().expect("tool response");
    client_write.shutdown().await.unwrap();
    drop(lines);
    session.abort();
    serde_json::from_str(&response).unwrap()
}

/// [`serve_on`] with a text error, so that a spawned task can hold it.
async fn serve_on_send(
    read: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    write: tokio::io::WriteHalf<tokio::io::DuplexStream>,
) -> Result<(), String> {
    serve_on(testnet_server(), BoundedTransport::over(read, write))
        .await
        .map_err(|e| e.to_string())
}

/// A field of the wrong type or an unknown variant is refused with the route
/// name and the fixed text, in the only content item.
#[tokio::test]
async fn a_rejected_argument_stays_out_of_the_tool_result() {
    let cases = [
        (
            "stellar_balances",
            json!({ "chain_id": "stellar:testnet", "account_id": "G", "assets": MARKER }),
        ),
        (
            "stellar_rule_create",
            json!({
                "chain_id": "stellar:testnet",
                "smart_account": "C",
                "signers": [{ "kind": MARKER }],
            }),
        ),
    ];
    for (tool, arguments) in cases {
        let response = tool_response(tool, arguments).await;
        let result = &response["result"];
        assert_eq!(result["isError"], true, "{response}");
        let content = result["content"].as_array().expect("content");
        assert_eq!(content.len(), 1, "{response}");
        assert_eq!(
            content[0]["text"],
            format!(
                "{tool}: the arguments have a missing field or a field of the wrong type or value"
            )
        );
        assert!(!response.to_string().contains(MARKER), "{response}");
    }
}

/// An unknown route answers rmcp's fixed text without the requested name.
#[tokio::test]
async fn an_unknown_route_name_is_not_interpolated() {
    let response = tool_response(&format!("{MARKER}_tool"), json!({})).await;
    assert_eq!(response["error"]["message"], "tool not found", "{response}");
    assert!(!response.to_string().contains(MARKER), "{response}");
}

/// The binary's final startup log states the refusal without the payload.
#[test]
fn the_startup_log_holds_no_rejected_message() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("profiles")).unwrap();
    std::fs::write(
        home.path().join("profiles").join("default.toml"),
        stellar_agent_test_support::profile_fixtures::noop_profile_toml(
            "default",
            "stellar:testnet",
            "https://soroban-testnet.stellar.org",
        ),
    )
    .unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_stellar-agent-mcp"))
        .args(["--profile", "default"])
        .env("STELLAR_AGENT_HOME", home.path())
        .env("STELLAR_AGENT_LOG", "trace")
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env(
            "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
            URL_SAFE_NO_PAD.encode([0x42; 32]),
        )
        .env_remove("STELLAR_AGENT_PROFILE")
        .env_remove("STELLAR_AGENT_CHAIN_ID")
        .env_remove("STELLAR_AGENT_RPC_URL")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&frame(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": { "cursor": MARKER },
        })))
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("the MCP client must open the session with an initialize request"),
        "{stderr}"
    );
    assert!(!stderr.contains(MARKER), "{stderr}");
}
