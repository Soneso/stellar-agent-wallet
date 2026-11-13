//! Both server routes preserve every stdout line and the library's tool set.

#![allow(clippy::expect_used, clippy::unwrap_used, reason = "test assertions")]

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{Value, json};
use serial_test::serial;
use stellar_agent_core::policy::McpToolRegistration;
use stellar_agent_mcp::inventory;

use super::unified_dispatch::Binary;

const DEADLINE: Duration = Duration::from_secs(30);
const ROUTES: [(&str, &[&str]); 2] = [("stellar-agent-mcp", &[]), ("wallet-x", &["mcp", "serve"])];

// Reap even when a protocol assertion fails with the child awaiting input.
struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub(super) fn session(binary: &Binary, args: &[&str]) -> (Vec<Value>, String) {
    let mut child = Process(
        Binary::spawn(
            binary
                .command(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )
        .expect("server starts"),
    );
    let mut input = child.0.stdin.take().expect("stdin");
    let stdout = child.0.stdout.take().expect("stdout");
    let mut stderr = child.0.stderr.take().expect("stderr");
    let (send_line, lines) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if send_line.send(line.expect("stdout line")).is_err() {
                break;
            }
        }
    });
    let errors = std::thread::spawn(move || {
        let mut text = String::new();
        stderr.read_to_string(&mut text).expect("stderr read");
        text
    });
    let mut responses = Vec::new();
    for request in [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2024-11-05","capabilities":{},
            "clientInfo":{"name":"unified-test","version":"1"}}}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
            "name":"stellar_enroll_owner_key","arguments":{}}}),
    ] {
        writeln!(input, "{request}").expect("write request");
        input.flush().expect("flush request");
        let line = lines
            .recv_timeout(DEADLINE)
            .expect("response before deadline");
        let response: Value = serde_json::from_str(&line).expect("every stdout line is JSON");
        assert!(response.is_object(), "{line}");
        assert_eq!(response["jsonrpc"], "2.0", "{line}");
        assert_eq!(response["id"], request["id"], "only a sent id: {line}");
        assert!(
            response.get("result").is_some() ^ response.get("error").is_some(),
            "{line}"
        );
        responses.push(response);
        if request["id"] == 1 {
            writeln!(
                input,
                "{}",
                json!({"jsonrpc":"2.0","method":"notifications/initialized"})
            )
            .expect("initialized notification");
            input.flush().expect("flush notification");
        }
    }
    drop(input);
    let status = child.0.wait().expect("server exits after EOF");
    reader.join().expect("stdout reader");
    let stderr = errors.join().expect("stderr reader");
    assert!(status.success(), "{status}: {stderr}");
    assert!(
        lines.try_iter().collect::<Vec<_>>().is_empty(),
        "no unsolicited stdout after responses"
    );
    (responses, stderr)
}

fn names(responses: &[Value]) -> BTreeSet<String> {
    let tools = responses[1]["result"]["tools"]
        .as_array()
        .expect("tools/list succeeds");
    let names: BTreeSet<_> = tools
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name").to_owned())
        .collect();
    assert_eq!(names.len(), tools.len(), "no duplicate tools");
    names
}

#[test]
#[serial]
fn stream_is_json_rpc() {
    for (name, args) in ROUTES {
        let (responses, _) = session(&Binary::new(name), args);
        assert_eq!(
            responses[0]["result"]["serverInfo"]["name"],
            "stellar-agent-mcp"
        );
    }
}

#[test]
#[serial]
fn tool_set_equals_library_registry() {
    // Force the server library into this test executable's link graph.
    let _ = stellar_agent_mcp::server::WalletServer::router_tool_names();
    let registry: BTreeSet<_> = inventory::iter::<McpToolRegistration>()
        .map(|entry| entry.name.to_owned())
        .collect();
    assert!(!registry.is_empty());
    for (name, args) in ROUTES {
        let binary = Binary::new(name);
        let (responses, _) = session(&binary, args);
        let served = names(&responses);
        let trace = std::fs::read_to_string(binary.home.path().join("trace"))
            .expect("server registry trace");
        let registered: BTreeSet<_> = trace
            .lines()
            .filter_map(|line| line.strip_prefix("tool:"))
            .map(str::to_owned)
            .collect();
        assert_eq!(served, registry, "served tools match the library registry");
        assert_eq!(
            registered, registry,
            "server registry matches the library registry"
        );
    }
}

#[test]
#[serial]
fn no_ceremony_tool() {
    for (name, args) in ROUTES {
        let (responses, _) = session(&Binary::new(name), args);
        assert_eq!(
            responses[2]["error"]["code"], -32602,
            "stellar_enroll_owner_key must be unknown: rmcp src/handler/server/router/tool.rs ToolRouter::call uses ErrorData::invalid_params; response: {}",
            responses[2]
        );
        for tool in names(&responses) {
            for denied in ["owner", "seed", "enroll", "sign_policy", "bind", "rotate"] {
                assert!(!tool.contains(denied), "ceremony handler: {tool}");
            }
        }
    }
}
