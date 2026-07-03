//! Subprocess tests for process-global subscriber installation paths.
//!
//! `init_subscriber_with` installs global tracing and optional log/panic
//! hooks, so install-path assertions run in a freshly spawned copy of this test
//! binary to avoid contaminating the parent test process.

#![allow(
    clippy::expect_used,
    clippy::print_stdout,
    reason = "integration harness reports subprocess status via stdout and treats setup failures as test failures"
)]

use std::process::{Command, ExitStatus};

use serde_json::Value;

const HELPER_ENV: &str = "STELLAR_AGENT_SUBSCRIBER_INSTALL_HELPER";

fn run_helper(scenario: &str) -> (ExitStatus, String, String) {
    let current_exe = std::env::current_exe().expect("current test binary path");
    let output = Command::new(current_exe)
        .args(["--exact", "helper_entrypoint", "--nocapture"])
        .env(HELPER_ENV, scenario)
        .output()
        .expect("helper process runs");

    (
        output.status,
        String::from_utf8(output.stdout).expect("helper stdout is UTF-8"),
        String::from_utf8(output.stderr).expect("helper stderr is UTF-8"),
    )
}

fn parse_helper_json(stdout: &str) -> Value {
    let json_line = stdout
        .lines()
        .find(|line| line.starts_with('{'))
        .expect("helper emits JSON status line");
    serde_json::from_str(json_line).expect("helper JSON parses")
}

#[test]
fn install_path_success_in_fresh_process() {
    let (status, stdout, stderr) = run_helper("once");
    assert!(status.success(), "stderr:\n{stderr}\nstdout:\n{stdout}");

    let json = parse_helper_json(&stdout);
    assert_eq!(json["scenario"], "once");
    assert_eq!(json["ok"], true);
}

#[test]
fn install_path_double_init_returns_init_error_in_fresh_process() {
    let (status, stdout, stderr) = run_helper("double");
    assert!(status.success(), "stderr:\n{stderr}\nstdout:\n{stdout}");

    let json = parse_helper_json(&stdout);
    assert_eq!(json["scenario"], "double");
    assert_eq!(json["first"], "ok");
    assert_eq!(json["second"], "init");
}

#[test]
fn helper_entrypoint() {
    let Ok(scenario) = std::env::var(HELPER_ENV) else {
        return;
    };

    let result = match scenario.as_str() {
        "once" => helper_once(),
        "double" => helper_double(),
        other => {
            println!(
                "{}",
                serde_json::json!({
                    "scenario": other,
                    "ok": false,
                    "error": "unknown scenario",
                })
            );
            std::process::exit(2);
        }
    };

    println!("{result}");
}

fn helper_config() -> stellar_agent_core::observability::SubscriberConfig {
    stellar_agent_core::observability::SubscriberConfig::default()
        .with_format_override(Some(stellar_agent_core::observability::FormatChoice::Json))
        .with_filter_override(Some(tracing_subscriber::EnvFilter::new("info")))
        .with_install_panic_hook(false)
}

fn helper_once() -> Value {
    let result = stellar_agent_core::observability::init_subscriber_with(helper_config());
    serde_json::json!({
        "scenario": "once",
        "ok": result.is_ok(),
        "error": result.err().map(|err| err.to_string()),
    })
}

fn helper_double() -> Value {
    let first = stellar_agent_core::observability::init_subscriber_with(
        helper_config().with_install_log_bridge(false),
    );
    let second = stellar_agent_core::observability::init_subscriber_with(
        helper_config().with_install_log_bridge(false),
    );

    serde_json::json!({
        "scenario": "double",
        "first": classify_result(&first),
        "second": classify_result(&second),
    })
}

fn classify_result(
    result: &Result<(), stellar_agent_core::observability::InitError>,
) -> &'static str {
    match result {
        Ok(()) => "ok",
        Err(stellar_agent_core::observability::InitError::Filter(_)) => "filter",
        Err(stellar_agent_core::observability::InitError::LogBridge(_)) => "log_bridge",
        Err(stellar_agent_core::observability::InitError::Init(_)) => "init",
        Err(_) => "other",
    }
}
