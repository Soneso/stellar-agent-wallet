//! Subprocess tests for the bound on the panic message the panic hook logs.
//!
//! The panic hook is process-global, so each scenario runs in a freshly
//! spawned copy of this test binary. The child installs the JSON subscriber
//! with the panic hook, panics inside `catch_unwind`, and the parent reads the
//! `panic_message` field from the JSON event the child wrote to stderr.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "integration harness treats setup failures as test failures"
)]

use std::process::Command;

use serde_json::Value;

const HELPER_ENV: &str = "STELLAR_AGENT_PANIC_HOOK_HELPER";

/// The hook's message cap in bytes (`PANIC_MESSAGE_MAX_BYTES`).
const PANIC_MESSAGE_MAX_BYTES: usize = 256;

/// Marker appended to a message longer than the cap.
const TRUNCATION_MARKER: &str = "...[TRUNCATED]";

/// Message that fits under the cap.
const SHORT_MESSAGE: &str = "short panic message";

/// Byte offset at which the secret strkey starts in the straddle scenario;
/// the 56-byte strkey spans the cap at 256.
const STRADDLE_OFFSET: usize = 236;

fn secret_strkey() -> String {
    stellar_strkey::Unredacted(&stellar_strkey::ed25519::PrivateKey([7u8; 32]))
        .to_string()
        .as_str()
        .to_owned()
}

fn straddle_message() -> String {
    let mut msg = "x".repeat(STRADDLE_OFFSET);
    msg.push_str(&secret_strkey());
    msg.push_str(&"y".repeat(64));
    msg
}

/// Runs the helper scenario and returns the JSON panic event it logged.
fn logged_panic_event(scenario: &str) -> Value {
    let current_exe = std::env::current_exe().expect("current test binary path");
    let output = Command::new(current_exe)
        .args([
            "--exact",
            "panic_hook_message_bound::helper_entrypoint",
            "--nocapture",
        ])
        .env(HELPER_ENV, scenario)
        .output()
        .expect("helper process runs");
    let stderr = String::from_utf8(output.stderr).expect("helper stderr is UTF-8");
    assert!(output.status.success(), "helper failed; stderr:\n{stderr}");

    stderr
        .lines()
        .filter(|line| line.starts_with('{'))
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|event| event["target"] == "stellar_agent_core::observability::panic")
        .unwrap_or_else(|| panic!("no panic event on stderr:\n{stderr}"))
}

/// Returns the `panic_message` field of a logged panic event.
fn panic_message(event: &Value) -> String {
    event["fields"]["panic_message"]
        .as_str()
        .unwrap_or_else(|| panic!("panic event carries no panic_message: {event}"))
        .to_owned()
}

#[test]
fn panic_hook_caps_a_long_message() {
    let event = logged_panic_event("long");
    let logged = panic_message(&event);
    assert_eq!(
        event["fields"]["panic_message_truncated"],
        Value::Bool(true),
        "a cut message carries the truncation flag: {event}"
    );

    assert!(
        logged.len() <= PANIC_MESSAGE_MAX_BYTES + TRUNCATION_MARKER.len(),
        "logged panic message is {} bytes",
        logged.len()
    );
    assert!(logged.ends_with(TRUNCATION_MARKER), "{logged}");
    assert!(logged.starts_with(&"q".repeat(64)), "{logged}");
}

#[test]
fn panic_hook_redacts_a_strkey_straddling_the_cap() {
    let strkey = secret_strkey();
    let event = logged_panic_event("straddle");
    let logged = panic_message(&event);
    assert_eq!(
        event["fields"]["panic_message_truncated"],
        Value::Bool(true),
        "a cut message carries the truncation flag: {event}"
    );

    assert!(
        logged.len() <= PANIC_MESSAGE_MAX_BYTES + TRUNCATION_MARKER.len(),
        "logged panic message is {} bytes",
        logged.len()
    );
    assert!(logged.starts_with(&"x".repeat(STRADDLE_OFFSET)), "{logged}");
    // No eight-character window of the strkey reaches the log.
    for start in 0..=strkey.len() - 8 {
        let fragment = &strkey[start..start + 8];
        assert!(
            !logged.contains(fragment),
            "logged panic message carries strkey fragment {fragment:?}: {logged}"
        );
    }
}

#[test]
fn panic_hook_logs_a_short_message_whole_without_the_truncation_flag() {
    let event = logged_panic_event("short");
    assert_eq!(panic_message(&event), SHORT_MESSAGE);
    assert!(
        event["fields"].get("panic_message_truncated").is_none(),
        "a message that fits carries no truncation flag: {event}"
    );
}

#[test]
fn helper_entrypoint() {
    let Ok(scenario) = std::env::var(HELPER_ENV) else {
        return;
    };
    let message = match scenario.as_str() {
        "long" => "q".repeat(10 * 1024),
        "short" => SHORT_MESSAGE.to_owned(),
        "straddle" => straddle_message(),
        other => panic!("unknown scenario {other}"),
    };

    let config = stellar_agent_core::observability::SubscriberConfig::default()
        .with_format_override(Some(stellar_agent_core::observability::FormatChoice::Json))
        .with_filter_override(Some(tracing_subscriber::EnvFilter::new("info")))
        .with_install_log_bridge(false)
        .with_install_panic_hook(true);
    stellar_agent_core::observability::init_subscriber_with(config)
        .expect("subscriber installs in a fresh process");

    let caught = std::panic::catch_unwind(move || panic!("{message}"));
    assert!(caught.is_err(), "the helper closure panics");
}
