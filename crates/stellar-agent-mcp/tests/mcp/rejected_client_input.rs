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
use std::time::Duration;

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

/// A request other than `ping` before `initialize` is refused with the fixed text,
/// and neither the error's forms nor its source chain hold the message.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn a_request_before_initialize_is_refused_without_its_payload() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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

/// The `tools/list` request with id 2 that follows each refused line.
fn tools_list() -> Vec<u8> {
    frame(&json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }))
}

/// The `-32700` answer without an `id` that refuses a line with `message`.
fn parse_error(message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "error": { "code": -32700, "message": message } })
}

/// The answer to a line over the line limit.
fn line_limit_error() -> Value {
    parse_error(&format!(
        "the frame exceeds the line limit of {STELLAR_AGENT_MCP_MAX_LINE_BYTES} bytes"
    ))
}

/// A line of `MARKER` repeats over the line limit, with its newline.
fn oversized_line() -> Vec<u8> {
    let mut line = MARKER.repeat(STELLAR_AGENT_MCP_MAX_LINE_BYTES / MARKER.len() + 2);
    line.push('\n');
    line.into_bytes()
}

/// `initialize`, `notifications/initialized`, `line`, and the `tools/list`
/// request with id 2.
fn after_initialize(line: &[u8]) -> Vec<u8> {
    let mut frames = frame(&initialize("2024-11-05"));
    frames.extend(frame(
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    ));
    frames.extend_from_slice(line);
    frames.extend(tools_list());
    frames
}

/// Serves a session whose client writes `frames` at once and reads the
/// server's answers up to the one with id 2, then closes its input.
///
/// Returns the answers in order and the outcome of the session.
async fn answers_up_to_id_2(frames: &[u8]) -> (Vec<Value>, Result<(), String>) {
    let (client, server_side) = tokio::io::duplex(4 << 20);
    let (server_read, server_write) = tokio::io::split(server_side);
    let session = tokio::spawn(serve_on_send(testnet_server(), server_read, server_write));
    let (client_read, mut client_write) = tokio::io::split(client);
    client_write.write_all(frames).await.unwrap();
    let mut lines = BufReader::new(client_read).lines();
    let mut answers = Vec::new();
    loop {
        let line = tokio::time::timeout(Duration::from_secs(30), lines.next_line())
            .await
            .expect("the server answers within the wait")
            .unwrap()
            .expect("the server answers id 2 before its output ends");
        let answer: Value = serde_json::from_str(&line).unwrap();
        let last = answer["id"] == 2;
        answers.push(answer);
        if last {
            break;
        }
    }
    client_write.shutdown().await.unwrap();
    let outcome = session.await.unwrap();
    (answers, outcome)
}

/// Asserts that `answers` hold the `initialize` result, `refusal` when it is
/// given, and the `tools/list` result for id 2, in that order.
fn assert_answers(answers: &[Value], refusal: Option<&Value>) {
    assert_eq!(answers[0]["id"], 1, "{answers:?}");
    assert!(answers[0]["result"].is_object(), "{answers:?}");
    let rest: Vec<&Value> = answers[1..answers.len() - 1].iter().collect();
    assert_eq!(rest, refusal.into_iter().collect::<Vec<_>>(), "{answers:?}");
    let listed = &answers[answers.len() - 1];
    assert_eq!(listed["id"], 2, "{answers:?}");
    assert!(listed["result"]["tools"].is_array(), "{answers:?}");
}

/// After `initialize`, a skipped or refused line leaves the session open: an
/// empty line and a `\r` line get no answer, a line that is not a JSON-RPC
/// message and one over the line limit get the `-32700` answer without an
/// `id`, and the next request is answered. No event holds the line.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn a_refused_line_after_initialize_leaves_the_session_open() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let malformed = parse_error("Parse error");
    let cases = [
        ("empty", b"\n".to_vec(), None, None),
        ("carriage return", b"\r\n".to_vec(), None, None),
        (
            "malformed JSON",
            format!("{{\"id\": \"{MARKER}\"\n").into_bytes(),
            Some(&malformed),
            Some("the frame is not a valid JSON-RPC message"),
        ),
        (
            "empty object",
            b"{}\n".to_vec(),
            Some(&malformed),
            Some("the frame is not a valid JSON-RPC message"),
        ),
        (
            "object the model refuses",
            frame(&json!({ MARKER: true })),
            Some(&malformed),
            Some("the frame is not a valid JSON-RPC message"),
        ),
        (
            "over the line limit",
            oversized_line(),
            Some(&line_limit_error()),
            Some("the frame exceeds the line limit"),
        ),
    ];
    for (case, line, refusal, event) in cases {
        let capture = TraceCapture::start(FormatChoice::Pretty);
        let (answers, outcome) = answers_up_to_id_2(&after_initialize(&line)).await;

        assert_answers(&answers, refusal);
        assert_eq!(outcome, Ok(()), "{case}");
        let logs = capture.logs();
        match event {
            Some(event) => assert!(logs.contains(event), "{case}: {logs}"),
            None => assert!(!logs.contains("the frame"), "{case}: {logs}"),
        }
        assert!(!logs.contains(MARKER), "{case}: {logs}");
        assert!(
            !answers
                .iter()
                .any(|answer| answer.to_string().contains(MARKER)),
            "{case}: {answers:?}"
        );
    }
}

/// A frame of malformed typed JSON is answered with the `-32700` answer, the
/// session goes on, and its event holds its position alone.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn a_malformed_frame_is_answered_and_logs_its_position_alone() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for format in [FormatChoice::Pretty, FormatChoice::Json] {
        let capture = TraceCapture::start(format);
        let (answers, outcome) = answers_up_to_id_2(&after_initialize(&frame(&json!({
            "jsonrpc": "2.0",
            "id": { MARKER: true },
            "method": 7,
            "params": MARKER,
        }))))
        .await;

        assert_answers(&answers, Some(&parse_error("Parse error")));
        assert_eq!(outcome, Ok(()));
        let logs = capture.logs();
        assert!(
            logs.contains("the frame is not a valid JSON-RPC message"),
            "{logs}"
        );
        assert!(logs.contains("column"), "{logs}");
        assert!(!logs.contains(MARKER), "{logs}");
    }
}

/// A frame over the line limit is answered with the line limit, the session
/// goes on, and its event is the fixed one.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn an_oversized_frame_is_answered_with_the_line_limit() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let capture = TraceCapture::start(FormatChoice::Pretty);
    let (answers, outcome) = answers_up_to_id_2(&after_initialize(&oversized_line())).await;

    assert_answers(&answers, Some(&line_limit_error()));
    assert_eq!(outcome, Ok(()));
    let logs = capture.logs();
    assert!(logs.contains("the frame exceeds the line limit"), "{logs}");
    assert!(!logs.contains(MARKER), "{logs}");
}

/// A malformed line or a line over the limit before `initialize` is answered
/// with its `-32700` answer, and the session goes on to serve `initialize`.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn a_refused_line_before_initialize_is_answered_and_initialize_is_served() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let cases = [
        (
            format!("{{\"id\": \"{MARKER}\"\n").into_bytes(),
            parse_error("Parse error"),
        ),
        (oversized_line(), line_limit_error()),
    ];
    for (line, refusal) in cases {
        let capture = TraceCapture::start(FormatChoice::Pretty);
        let mut frames = line;
        frames.extend(after_initialize(b""));
        let (answers, outcome) = answers_up_to_id_2(&frames).await;

        assert_eq!(answers.len(), 3, "{answers:?}");
        assert_eq!(answers[0], refusal);
        assert_answers(&answers[1..], None);
        assert_eq!(outcome, Ok(()));
        let logs = capture.logs();
        assert!(logs.contains("MCP server ready"), "{logs}");
        assert!(!logs.contains(MARKER), "{logs}");
    }
}

/// A `ping` request before `initialize` is answered, and the session goes on
/// to serve `initialize` and the next request. The test pins rmcp's handshake
/// through the wallet's transport, as the guard of the documented first-message
/// rule.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn a_ping_before_initialize_is_answered_and_initialize_is_served() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let mut frames = frame(&json!({ "jsonrpc": "2.0", "id": 7, "method": "ping" }));
    frames.extend(after_initialize(b""));
    let (answers, outcome) = answers_up_to_id_2(&frames).await;

    assert_eq!(answers.len(), 3, "{answers:?}");
    assert_eq!(
        answers[0],
        json!({ "jsonrpc": "2.0", "id": 7, "result": {} })
    );
    assert_answers(&answers[1..], None);
    assert_eq!(outcome, Ok(()));
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
#[serial_test::serial]
async fn a_read_failure_logs_the_io_kind() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
#[serial_test::serial]
async fn held_rmcp_events_stay_out_of_a_real_session() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
#[serial_test::serial]
async fn a_rejected_argument_stays_out_of_the_log() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
    tool_response_on(testnet_server(), name, arguments).await
}

/// The tool call response for `name` with `arguments` from `server`.
async fn tool_response_on(server: WalletServer, name: &str, arguments: Value) -> Value {
    let (client, server_side) = tokio::io::duplex(1 << 20);
    let (server_read, server_write) = tokio::io::split(server_side);
    let session = tokio::spawn(async move {
        let _ = serve_on_send(server, server_read, server_write).await;
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
    server: WalletServer,
    read: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    write: tokio::io::WriteHalf<tokio::io::DuplexStream>,
) -> Result<(), String> {
    serve_on(server, BoundedTransport::over(read, write))
        .await
        .map_err(|e| e.to_string())
}

/// A field of the wrong type or an unknown variant is refused with the route
/// name and the fixed text, in the only content item.
#[tokio::test]
#[serial_test::serial]
async fn a_rejected_argument_stays_out_of_the_tool_result() {
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    assert!(
        home.path()
            .join(stellar_agent_test_support::sandbox::MARKER)
            .is_file(),
        "owned wallet root is marked before the home guard"
    );
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
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

/// Off mainnet every classic commit requires its envelope, protocol nonce
/// and nonce expiry. A commit that omits one answers the same fixed tool
/// result on all four tools; a present empty envelope refuses
/// `simulation.divergence`. A payment commit with a present empty nonce or a
/// zero expiry beside an envelope that does not decode keeps that refusal
/// too.
#[tokio::test]
#[serial_test::serial]
async fn a_classic_commit_without_its_envelope_fields_answers_the_fixed_refusal() {
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
    let account = stellar_agent_test_support::signed_envelope::account_id_for_seed([5; 32]);
    let other = stellar_agent_test_support::signed_envelope::account_id_for_seed([6; 32]);
    let base = json!({ "chain_id": "stellar:testnet", "nonce": "AAAA",
        "expires_at_unix_ms": 1, "envelope_xdr": "AAAA" });
    let tools = [
        (
            "stellar_pay_commit",
            json!({ "source": account, "destination": other, "amount": "1 XLM", "asset": "native" }),
        ),
        (
            "stellar_create_account_commit",
            json!({ "source": account, "destination": other, "starting_balance": "1 XLM" }),
        ),
        ("stellar_trustline_commit", json!({ "from": account })),
        (
            "stellar_claim_commit",
            json!({ "balance_id": "ab".repeat(32), "source_account": account }),
        ),
    ];
    for (tool, own) in tools {
        let mut complete = base.clone();
        complete
            .as_object_mut()
            .unwrap()
            .extend(own.as_object().unwrap().clone());
        for field in ["nonce", "expires_at_unix_ms", "envelope_xdr"] {
            let mut arguments = complete.clone();
            arguments.as_object_mut().unwrap().remove(field);
            let response = tool_response(tool, arguments).await;
            let result = &response["result"];
            assert_eq!(result["isError"], true, "{tool} {field}: {response}");
            assert_eq!(
                result["content"][0]["text"],
                format!(
                    "{tool}: the arguments have a missing field or a field of the wrong type or value"
                ),
                "{tool} {field}: {response}"
            );
        }
        let mut present = vec![("envelope_xdr", json!(""))];
        if tool == "stellar_pay_commit" {
            present.extend([("nonce", json!("")), ("expires_at_unix_ms", json!(0))]);
        }
        for (field, value) in present {
            let mut arguments = complete.clone();
            arguments[field] = value;
            let response = tool_response(tool, arguments).await;
            let text = response["result"]["content"][0]["text"].as_str().unwrap();
            let envelope: Value = serde_json::from_str(text).unwrap();
            assert_eq!(
                envelope["error"]["code"], "simulation.divergence",
                "{tool} {field}: {response}"
            );
        }
    }
}

/// The unsigned envelope of `source` with the one operation `body`.
fn testnet_envelope(source: &str, body: stellar_xdr::OperationBody) -> String {
    use stellar_xdr::{
        Limits, Memo, MuxedAccount, Operation, Preconditions, SequenceNumber, Transaction,
        TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, VecM, WriteXdr,
    };
    let key = stellar_strkey::ed25519::PublicKey::from_string(source)
        .unwrap()
        .0;
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(key)),
            fee: 100,
            seq_num: SequenceNumber(101),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body,
            }]
            .try_into()
            .unwrap(),
            ext: TransactionExt::V0,
        },
        signatures: VecM::default(),
    })
    .to_xdr_base64(Limits::none())
    .unwrap()
}

fn testnet_account_id(account: &str) -> stellar_xdr::AccountId {
    stellar_xdr::AccountId(stellar_xdr::PublicKey::PublicKeyTypeEd25519(
        stellar_xdr::Uint256(
            stellar_strkey::ed25519::PublicKey::from_string(account)
                .unwrap()
                .0,
        ),
    ))
}

/// On testnet a present empty `nonce` or a zero `expires_at_unix_ms` with a
/// valid envelope reaches the nonce check and answers the uniform nonce
/// refusal `nonce.expired`, as on a mainnet envelope record, for the
/// create-account, trustline and claim commits. The endpoint serves the
/// testnet, the funded source, the trustline issuer and the claimable
/// balance, so each call passes the checks before the nonce.
#[tokio::test]
#[serial_test::serial]
async fn a_present_empty_nonce_or_zero_expiry_answers_the_nonce_refusal_on_testnet() {
    use stellar_agent_test_support::xdr_fixtures::{
        account_entry_xdr_with_seq, account_ledger_key_xdr,
    };
    use stellar_xdr::{
        AlphaNum4, Asset, AssetCode4, ChangeTrustAsset, ChangeTrustOp, ClaimClaimableBalanceOp,
        ClaimPredicate, ClaimableBalanceEntry, ClaimableBalanceEntryExt, ClaimableBalanceId,
        Claimant, ClaimantV0, CreateAccountOp, Hash, LedgerEntryData, LedgerKey,
        LedgerKeyClaimableBalance, Limits, OperationBody, WriteXdr,
    };
    let _data_root = crate::common::isolated_data_root();
    stellar_agent_test_support::keyring_mock::install().unwrap();
    let account = stellar_agent_test_support::signed_envelope::account_id_for_seed([5; 32]);
    let other = stellar_agent_test_support::signed_envelope::account_id_for_seed([6; 32]);
    let issuer = stellar_agent_test_support::signed_envelope::account_id_for_seed([7; 32]);
    let balance_id = ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([0xab; 32]));
    let balance_key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
        balance_id: balance_id.clone(),
    })
    .to_xdr_base64(Limits::none())
    .unwrap();
    let balance_entry = LedgerEntryData::ClaimableBalance(ClaimableBalanceEntry {
        balance_id: balance_id.clone(),
        claimants: vec![Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: testnet_account_id(&account),
            predicate: ClaimPredicate::Unconditional,
        })]
        .try_into()
        .unwrap(),
        asset: Asset::Native,
        amount: 10,
        ext: ClaimableBalanceEntryExt::V0,
    })
    .to_xdr_base64(Limits::none())
    .unwrap();
    let endpoint = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            crate::common::TimeoutRpc::new(vec![
                (
                    account_ledger_key_xdr(&account),
                    account_entry_xdr_with_seq(&account, 100_000_000_000_000, 0, 100),
                ),
                (
                    account_ledger_key_xdr(&issuer),
                    account_entry_xdr_with_seq(&issuer, 100_000_000_000, 0, 1),
                ),
                (balance_key, balance_entry),
            ])
            .with_network(crate::common::EndpointNetwork::testnet()),
        )
        .mount(&endpoint)
        .await;
    let mut profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    profile.rpc_url = endpoint.uri();
    crate::common::install_test_audit_key(&mut profile);

    let usd = AlphaNum4 {
        asset_code: AssetCode4(*b"USD\0"),
        issuer: testnet_account_id(&issuer),
    };
    let tools = [
        (
            "stellar_create_account_commit",
            json!({ "source": account, "destination": other, "starting_balance": "1 XLM" }),
            OperationBody::CreateAccount(CreateAccountOp {
                destination: testnet_account_id(&other),
                starting_balance: 10_000_000,
            }),
        ),
        (
            "stellar_trustline_commit",
            json!({ "from": account }),
            OperationBody::ChangeTrust(ChangeTrustOp {
                line: ChangeTrustAsset::CreditAlphanum4(usd),
                limit: 10,
            }),
        ),
        (
            "stellar_claim_commit",
            json!({ "balance_id": "ab".repeat(32), "source_account": account }),
            OperationBody::ClaimClaimableBalance(ClaimClaimableBalanceOp { balance_id }),
        ),
    ];
    let valid_nonce = URL_SAFE_NO_PAD.encode([0; 48]);
    for (tool, own, body) in tools {
        for (field, nonce, expires_at_unix_ms) in [
            ("nonce", json!(""), json!(u64::MAX)),
            ("expires_at_unix_ms", json!(valid_nonce), json!(0)),
        ] {
            let mut arguments = own.clone();
            let object = arguments.as_object_mut().unwrap();
            object.insert("chain_id".to_owned(), json!("stellar:testnet"));
            object.insert(
                "envelope_xdr".to_owned(),
                json!(testnet_envelope(&account, body.clone())),
            );
            object.insert("nonce".to_owned(), nonce);
            object.insert("expires_at_unix_ms".to_owned(), expires_at_unix_ms);
            let server = WalletServer::new(profile.clone()).unwrap();
            let response = tool_response_on(server, tool, arguments).await;
            let text = response["result"]["content"][0]["text"].as_str().unwrap();
            let envelope: Value = serde_json::from_str(text).unwrap();
            assert_eq!(
                envelope["error"]["code"], "nonce.expired",
                "{tool} {field}: {response}"
            );
        }
    }
}

/// An unknown route answers rmcp's fixed text without the requested name.
#[tokio::test]
#[serial_test::serial]
async fn an_unknown_route_name_is_not_interpolated() {
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    assert!(
        home.path()
            .join(stellar_agent_test_support::sandbox::MARKER)
            .is_file(),
        "owned wallet root is marked before the home guard"
    );
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
    let response = tool_response(&format!("{MARKER}_tool"), json!({})).await;
    assert_eq!(response["error"]["message"], "tool not found", "{response}");
    assert!(!response.to_string().contains(MARKER), "{response}");
}

/// The binary's final startup log states the refusal without the payload.
#[test]
fn the_startup_log_holds_no_rejected_message() {
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
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
    let mut child = crate::common::server_binary::server_command(home.path())
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
