//! Rejected CLI values stay out of the events the commands emit on the way
//! to their refusals. Each case proves the event fired before it proves the
//! value is absent.
#![allow(clippy::expect_used, clippy::panic, reason = "test assertions")]

use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use serial_test::serial;
use stellar_agent_core::audit_log::AuditBinding;
use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
use stellar_agent_core::profile::loader::save_new_to_dir;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::keyring::KeyringAuditBindingStore;
use stellar_agent_smart_account::ed25519_verifier::ED25519_VERIFIER_WASM_SHA256;
use stellar_agent_smart_account::verifiers::VerifierRegistry;
use stellar_agent_smart_account::webauthn_verifier::WEBAUTHN_VERIFIER_WASM_SHA256;
use stellar_agent_test_support::rejected_value::assert_no_marker_in_text;
use stellar_agent_test_support::signed_envelope::{account_id_for_seed, get_network_result};
use stellar_agent_test_support::xdr_fixtures::{account_entry_xdr, account_ledger_key_xdr};
use stellar_xdr::WriteXdr as _;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const HEADLESS_KEY: [u8; 32] = [0x42; 32];
const PROFILE: &str = "marker-events";
const MARKER: &str = "credmarker7";
const ACCOUNT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
const SECRET_VAR: &str = "EVENT_FIXTURE_SIGNER_SECRET";
/// An identifier whose two ends are the forms an abbreviation of it shows.
const OPERATION_ID: &str = "c0ffee42abababababababababababababababababababababababab1ced7ea5";

fn run(home: &Path, args: &[&str], log_format: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_stellar-agent"));
    command
        .args(args)
        .env("STELLAR_AGENT_HOME", home)
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env(
            "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
            URL_SAFE_NO_PAD.encode(HEADLESS_KEY),
        )
        .env(
            SECRET_VAR,
            stellar_strkey::ed25519::PrivateKey([7; 32])
                .as_unredacted()
                .to_string()
                .as_str(),
        )
        .env("STELLAR_AGENT_LOG", "trace")
        .env("STELLAR_AGENT_LOG_FORMAT", log_format)
        .env_remove("STELLAR_AGENT_PROFILE")
        .env_remove("STELLAR_AGENT_CHAIN_ID")
        .env_remove("STELLAR_AGENT_RPC_URL")
        .env_remove("STELLAR_AGENT_SECONDARY_RPC_URL");
    let registry = home.join("networks.toml");
    if registry.exists() {
        command.env("STELLAR_AGENT_NETWORKS_TOML", registry);
    }
    command.output().expect("CLI executes")
}

/// Asserts that the run emitted `message`, and that neither stream holds the
/// marker in any case.
fn assert_event_without_marker(output: &Output, message: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(message), "missing {message:?}: {stderr}");
    for text in [&stdout, &stderr] {
        assert!(!text.to_lowercase().contains(MARKER), "{text}");
    }
}

/// The JSON envelope of a run.
fn envelope_of(output: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .unwrap_or_else(|| panic!("no JSON envelope: {stdout}"));
    serde_json::from_str(line).expect("JSON envelope")
}

/// The error object of a refused run.
fn error_of(output: &Output) -> Value {
    let envelope = envelope_of(output);
    assert_eq!(envelope["ok"], false, "{envelope}");
    envelope["error"].clone()
}

/// The data object of a successful run.
fn data_of(output: &Output) -> Value {
    let envelope = envelope_of(output);
    assert_eq!(envelope["ok"], true, "{envelope}");
    envelope["data"].clone()
}

/// Persists a testnet profile over `rpc_url` with its audit key minted and
/// its binding recorded in the headless store the child opens. The secondary
/// endpoint names the same server under a second loopback host, which the
/// signing path's local secondary-endpoint check accepts.
fn save_profile(home: &Path, rpc_url: &str) {
    save_profile_with_audit_log(
        home,
        rpc_url,
        &home.join("audit").join(format!("{PROFILE}.jsonl")),
    );
}

/// [`save_profile`] with `audit_log_path`.
fn save_profile_with_audit_log(home: &Path, rpc_url: &str, audit_log_path: &Path) {
    let profile = Profile::builder_testnet_named(PROFILE, "s", "a", "n", "a")
        .rpc_url(rpc_url)
        .secondary_rpc_url(stellar_agent_test_support::second_loopback_host(rpc_url))
        .audit_log_path(audit_log_path)
        .with_noop_engine()
        .build();
    let store: Arc<keyring_core::CredentialStore> =
        Arc::new(stellar_agent_headless_keyring::store::HeadlessStore::new(
            home.join("headless-keyring").join("store.keyring"),
            stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                zeroize::Zeroizing::new(HEADLESS_KEY),
            )),
        ));
    keyring_core::set_default_store(store);
    let coordinate = &profile.audit_log_hash_chain_key_id;
    keyring_core::Entry::new(&coordinate.service, &coordinate.account)
        .expect("audit key entry")
        .set_password(&URL_SAFE_NO_PAD.encode([0x2c; 32]))
        .expect("audit key");
    KeyringAuditBindingStore::for_profile(PROFILE)
        .store(&AuditBinding::for_profile(&profile))
        .expect("audit binding");
    save_new_to_dir(PROFILE, &profile, &home.join("profiles")).expect("profile fixture");
}

/// The timelock verbs emit their submit events without the addresses and the
/// function name, in the marker form and with a long or non-ASCII value.
#[test]
#[serial]
fn timelock_events_hold_no_argument() {
    let home = tempfile::tempdir().expect("home");
    save_profile(home.path(), "http://127.0.0.1:1");
    let hex = "ab".repeat(32);
    let long_function = format!("{MARKER}{}", "x".repeat(600));
    let unicode = format!("{MARKER}\u{e9}\u{1F600}");
    for (address, function) in [(MARKER, MARKER), (unicode.as_str(), long_function.as_str())] {
        let signer = ["--signer-secret-env", SECRET_VAR];
        let common = ["--profile", PROFILE, "--timelock", address];
        let target_and_function = ["--target", address, "--function", function];
        let cases: [(Vec<&str>, &str, &str); 4] = [
            (
                [
                    &["smart-account", "timelock", "execute"][..],
                    &common,
                    &signer,
                    &target_and_function,
                    &["--operation-id", &hex, "--salt", &hex],
                ]
                .concat(),
                "smart-account timelock execute: submitting",
                "sa.deployment_failed",
            ),
            (
                [
                    &["smart-account", "timelock", "schedule"][..],
                    &common,
                    &signer,
                    &target_and_function,
                    &["--delay-ledgers", "10"],
                ]
                .concat(),
                "smart-account timelock schedule: submitting",
                "sa.timelock_schedule_failed",
            ),
            (
                [
                    &["smart-account", "timelock", "cancel"][..],
                    &common,
                    &signer,
                    &["--operation-id", &hex],
                ]
                .concat(),
                "smart-account timelock cancel: submitting",
                "sa.timelock_cancel_failed",
            ),
            (
                [&["smart-account", "timelock", "list-pending"][..], &common].concat(),
                "smart-account timelock list-pending: querying pending operations",
                "sa.timelock_list_pending_failed",
            ),
        ];
        for (args, message, code) in cases {
            let output = run(home.path(), &args, "pretty");
            assert_event_without_marker(&output, message);
            assert_eq!(error_of(&output)["code"], code, "{output:?}");
        }
    }
}

/// Answers as a testnet endpoint: every simulation with `simulation`, and
/// every ledger read with the signer's account.
struct TimelockEndpoint {
    account_key: String,
    account_entry: String,
    simulation: Value,
}

impl Respond for TimelockEndpoint {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).expect("JSON-RPC request");
        let id = body["id"].clone();
        let result = match body["method"].as_str().unwrap_or_default() {
            "getNetwork" => get_network_result(TESTNET_PASSPHRASE),
            "getLatestLedger" => json!({
                "id": "ab".repeat(32), "sequence": 1000, "protocolVersion": 27
            }),
            "simulateTransaction" => self.simulation.clone(),
            "getLedgerEntries" => json!({
                "entries": [{
                    "key": self.account_key,
                    "xdr": self.account_entry,
                    "lastModifiedLedgerSeq": 100
                }],
                "latestLedger": 1000
            }),
            other => panic!("the fixture does not serve {other}"),
        };
        ResponseTemplate::new(200)
            .set_body_json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
    }
}

/// Runs `args` against [`TimelockEndpoint`] with a saved profile.
async fn run_against_timelock(simulation: Value, args: Vec<String>) -> Output {
    let server = MockServer::start().await;
    let signer = account_id_for_seed([7; 32]);
    Mock::given(method("POST"))
        .respond_with(TimelockEndpoint {
            account_key: account_ledger_key_xdr(&signer),
            account_entry: account_entry_xdr(&signer, 100_000_000, 0),
            simulation,
        })
        .mount(&server)
        .await;
    let home = tempfile::tempdir().expect("home");
    save_profile(home.path(), &server.uri());
    tokio::task::spawn_blocking(move || {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        run(home.path(), &args, "pretty")
    })
    .await
    .expect("the CLI task completes")
}

/// Asserts that the run emitted `message` and holds neither end of `OPERATION_ID`,
/// so neither the identifier nor an abbreviation of it reaches a stream.
fn assert_event_without_operation_id(output: &Output, message: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(message), "missing {message:?}: {stderr}");
    for text in [&stdout, &stderr] {
        for end in [&OPERATION_ID[..8], &OPERATION_ID[56..]] {
            assert!(!text.contains(end), "{text}");
        }
    }
}

/// The arguments of a timelock verb over [`OPERATION_ID`].
fn timelock_args(verb: &str, rest: &[&str]) -> Vec<String> {
    ["smart-account", "timelock", verb, "--profile", PROFILE]
        .iter()
        .chain(&["--timelock", ACCOUNT, "--signer-secret-env", SECRET_VAR])
        .chain(rest)
        .map(|arg| (*arg).to_owned())
        .collect()
}

/// A cancel that the contract refuses for an operation that was never
/// scheduled keeps the identifier out of its submit event, its events and its
/// envelope, which states the check.
#[tokio::test]
#[serial]
async fn timelock_cancel_of_a_never_scheduled_operation_holds_no_operation_id() {
    let output = run_against_timelock(
        json!({"error": "HostError: Error(Contract, #4002)", "latestLedger": 1000}),
        timelock_args("cancel", &["--operation-id", OPERATION_ID]),
    )
    .await;
    assert_event_without_operation_id(&output, "smart-account timelock cancel: submitting");
    let error = error_of(&output);
    assert_eq!(error["code"], "sa.timelock_cancel_failed", "{error}");
    let message = error["message"].as_str().expect("message");
    assert!(
        message.ends_with("; operation_id must identify a pending scheduled operation"),
        "{message}"
    );
}

/// An execute that the pending-state check refuses keeps the identifier out
/// of its submit event, its events and its envelope.
#[tokio::test]
#[serial]
async fn timelock_execute_of_a_never_scheduled_operation_holds_no_operation_id() {
    // `get_operation_ledger` answers 0, the contract's unset ledger.
    let unset_ledger = stellar_xdr::ScVal::U32(0)
        .to_xdr_base64(stellar_xdr::Limits::none())
        .expect("ScVal encodes");
    let output = run_against_timelock(
        json!({
            "results": [{"auth": [], "xdr": unset_ledger}],
            "minResourceFee": "100",
            "latestLedger": 1000
        }),
        timelock_args(
            "execute",
            &[
                "--target",
                ACCOUNT,
                "--function",
                "transfer",
                "--operation-id",
                OPERATION_ID,
                "--salt",
                OPERATION_ID,
            ],
        ),
    )
    .await;
    assert_event_without_operation_id(&output, "smart-account timelock execute: submitting");
    let error = error_of(&output);
    assert_eq!(error["code"], "sa.timelock_execute_failed", "{error}");
}

/// A pool size outside the range is refused before the profile loads, with
/// the check and without the size, on both streams.
#[test]
#[serial]
fn pool_size_refusal_holds_no_size() {
    const REFUSED_SIZE: &str = "4242424";
    let home = tempfile::tempdir().expect("home");
    let output = run(
        home.path(),
        &["pool", "init", "--size", REFUSED_SIZE],
        "pretty",
    );
    assert_eq!(
        error_of(&output)["message"],
        "unexpected internal state: pool.size_out_of_range: pool size (--size) must be an \
         integer from 1 through 19 so all transaction signatures fit"
    );
    for text in [&output.stdout, &output.stderr] {
        assert_no_marker_in_text(&String::from_utf8_lossy(text), REFUSED_SIZE);
    }
}

/// The rules-list dispatch event and its refusal hold no account.
#[test]
#[serial]
fn rules_list_event_holds_no_account() {
    let home = tempfile::tempdir().expect("home");
    save_profile(home.path(), "http://127.0.0.1:1");
    let output = run(
        home.path(),
        &[
            "smart-account",
            "rules",
            "list",
            "--profile",
            PROFILE,
            "--account",
            MARKER,
        ],
        "pretty",
    );
    assert_event_without_marker(
        &output,
        "smart-account rules list: dispatching to list-rules handler",
    );
}

/// A refused home domain stays out of the refresh failure event, which keeps
/// the error class.
#[test]
#[serial]
fn counterparty_refresh_event_holds_no_home_domain() {
    let home = tempfile::tempdir().expect("home");
    save_profile(home.path(), "http://127.0.0.1:1");
    let output = run(
        home.path(),
        &[
            "counterparty",
            "refresh",
            "--profile",
            PROFILE,
            "credmarker7_invalid.example",
        ],
        "pretty",
    );
    assert_event_without_marker(&output, "counterparty refresh failed");
}

/// The approval reports of a name that resolves to no saved profile keep
/// their counts, and the name stays out of the events, the envelope and the
/// table. A saved profile keeps its name in the envelope and the table.
#[test]
#[serial]
fn approval_reports_hold_no_unsaved_profile() {
    let home = tempfile::tempdir().expect("home");
    save_profile(home.path(), "http://127.0.0.1:1");
    for (verb, message, count) in [
        ("list", "approval list completed", "pending_count"),
        ("gc", "approval gc completed", "evicted"),
    ] {
        let output = run(
            home.path(),
            &["approve", verb, "--profile", MARKER],
            "pretty",
        );
        assert_event_without_marker(&output, message);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(count),
            "{output:?}"
        );
        let data = data_of(&output);
        assert!(data.get("profile").is_none(), "{data}");
        match verb {
            "list" => {
                assert_eq!(data["pending"], json!([]), "{data}");
                assert_eq!(data["expired_count"], 0, "{data}");
            }
            _ => assert_eq!(data["evicted_count"], 0, "{data}"),
        }
        let saved = run(
            home.path(),
            &["approve", verb, "--profile", PROFILE],
            "pretty",
        );
        assert_eq!(data_of(&saved)["profile"], PROFILE);
    }
    let table = |profile| {
        run(
            home.path(),
            &["approve", "list", "--profile", profile, "--output", "table"],
            "pretty",
        )
    };
    let output = table(MARKER);
    assert_event_without_marker(&output, "approval list completed");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "No pending approvals."
    );
    assert_eq!(
        String::from_utf8_lossy(&table(PROFILE).stdout).trim(),
        format!("No pending approvals for profile '{PROFILE}'.")
    );
}

/// A refused asset stays out of the trustline refusal event.
#[test]
#[serial]
fn trustline_refusal_event_holds_no_asset() {
    let home = tempfile::tempdir().expect("home");
    save_profile(home.path(), "http://127.0.0.1:1");
    let from = stellar_strkey::ed25519::PublicKey([1; 32]).to_string();
    for asset in [MARKER, "CODE:credmarker7"] {
        let output = run(
            home.path(),
            &[
                "trustline",
                "--profile",
                PROFILE,
                "--from",
                from.as_str(),
                "--asset",
                asset,
            ],
            "pretty",
        );
        assert_event_without_marker(&output, "denomination resolver refused trustline");
    }
}

/// An `--arg` or `--install-param` value that is neither base64 nor XDR is
/// refused at its position with one reason and no decoder diagnostic.
#[test]
#[serial]
fn xdr_arguments_report_the_accepted_form() {
    let home = tempfile::tempdir().expect("home");
    save_profile(home.path(), "http://127.0.0.1:1");
    let verifier = stellar_strkey::Contract([0x32; 32]).to_string();
    for value in ["~", "AAAA"] {
        let execute = run(
            home.path(),
            &[
                "smart-account",
                "execute",
                "--profile",
                PROFILE,
                "--account",
                ACCOUNT,
                "--contract",
                ACCOUNT,
                "--function",
                "transfer",
                "--auth-rule-id",
                "1",
                "--signer-secret-env",
                SECRET_VAR,
                "--rule-signer-ed25519-secret-env",
                SECRET_VAR,
                "--verifier",
                verifier.as_str(),
                "--arg",
                value,
            ],
            "pretty",
        );
        let error = error_of(&execute);
        assert_eq!(
            error["code"], "validation.xdr_argument_malformed",
            "{error}"
        );
        let message = error["message"].as_str().expect("message");
        assert!(message.contains("arg[0]"), "{message}");
        assert!(
            message.contains("must be base64-encoded ScVal XDR"),
            "{message}"
        );
        assert!(!message.contains("Invalid symbol"), "{message}");

        let add_policy = run(
            home.path(),
            &[
                "smart-account",
                "rules",
                "add-policy",
                "--profile",
                PROFILE,
                "--account",
                ACCOUNT,
                "--rule-id",
                "1",
                "--kind",
                "raw",
                "--policy-address",
                ACCOUNT,
                "--signer-secret-env",
                SECRET_VAR,
                "--install-param",
                value,
            ],
            "pretty",
        );
        let error = error_of(&add_policy);
        assert_eq!(
            error["code"], "validation.xdr_argument_malformed",
            "{error}"
        );
        let message = error["message"].as_str().expect("message");
        assert!(message.contains("install-param"), "{message}");
        assert!(
            message.contains("must be base64-encoded ScVal XDR"),
            "{message}"
        );
        assert!(!message.contains("Invalid symbol"), "{message}");
    }
}

/// Answers every simulation with the contract's `ContextRuleNotFound` panic,
/// and every ledger read with the signer's account.
struct MissingRule {
    account_key: String,
    account_entry: String,
}

impl Respond for MissingRule {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).expect("JSON-RPC request");
        let id = body["id"].clone();
        let reply = match body["method"].as_str().unwrap_or_default() {
            "simulateTransaction" => json!({"jsonrpc": "2.0", "id": id, "result": {
                "error": "HostError: Error(Contract, #3000)",
                "latestLedger": 1000
            }}),
            "getLedgerEntries" => json!({"jsonrpc": "2.0", "id": id, "result": {
                "entries": [{
                    "key": self.account_key,
                    "xdr": self.account_entry,
                    "lastModifiedLedgerSeq": 100
                }],
                "latestLedger": 1000
            }}),
            other => json!({"jsonrpc": "2.0", "id": id, "error": {
                "code": -32601,
                "message": format!("the fixture does not serve {other}")
            }}),
        };
        ResponseTemplate::new(200).set_body_json(reply)
    }
}

/// A rule id the account does not hold reaches the missing-rule branch and
/// stays out of the refusal.
#[tokio::test]
#[serial]
async fn missing_rule_refusal_holds_no_rule_id() {
    let server = MockServer::start().await;
    let signer = account_id_for_seed([7; 32]);
    Mock::given(method("POST"))
        .respond_with(MissingRule {
            account_key: account_ledger_key_xdr(&signer),
            account_entry: account_entry_xdr(&signer, 100_000_000, 0),
        })
        .mount(&server)
        .await;
    let home = tempfile::tempdir().expect("home");
    save_profile(home.path(), &server.uri());
    let policy = stellar_strkey::Contract([0x32; 32]).to_string();
    let home_path = home.path().to_owned();
    let output = tokio::task::spawn_blocking(move || {
        let args = [
            "smart-account",
            "rules",
            "add-policy",
            "--profile",
            PROFILE,
            "--account",
            ACCOUNT,
            "--rule-id",
            "4242424",
            "--kind",
            "raw",
            "--policy-address",
            policy.as_str(),
            "--signer-secret-env",
            SECRET_VAR,
            "--install-param",
            "AAAAAQ==",
        ];
        run(&home_path, &args, "pretty")
    })
    .await
    .expect("CLI task");

    let error = error_of(&output);
    assert_eq!(
        error["message"],
        "--rule-id must identify a rule on the smart account; run 'smart-account list-rules' to \
         list the rules"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("4242424"), "{stdout}");
}

/// A rule id the account does not hold stays out of the spending-limit submit
/// event, which runs before the manager reads the rule, and out of the
/// refusal.
#[tokio::test]
#[serial]
async fn spending_limit_submit_event_holds_no_rule_id() {
    let output = run_against_timelock(
        json!({"error": "HostError: Error(Contract, #3000)", "latestLedger": 1000}),
        [
            "smart-account",
            "rules",
            "set-spending-limit",
            "--profile",
            PROFILE,
            "--account",
            ACCOUNT,
            "--rule-id",
            "4242424",
            "--limit",
            "100",
            "--signer-secret-env",
            SECRET_VAR,
        ]
        .map(str::to_owned)
        .to_vec(),
    )
    .await;
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("smart-account rules set-spending-limit: submitting set_spending_limit"),
        "{output:?}"
    );
    assert_eq!(
        error_of(&output)["code"],
        "sa.deployment_failed",
        "{output:?}"
    );
    for text in [&output.stdout, &output.stderr] {
        assert_no_marker_in_text(&String::from_utf8_lossy(text), "4242424");
    }
}

/// A rule id the account does not hold passes the signer-cap read and stays
/// out of the add submit event, which runs before the manager refuses the
/// rule for its missing baseline, and out of the refusal.
#[tokio::test]
#[serial]
async fn signers_add_submit_event_holds_no_missing_rule_id() {
    let delegated = account_id_for_seed([9; 32]);
    let output = run_against_timelock(
        json!({"error": "HostError: Error(Contract, #3000)", "latestLedger": 1000}),
        [
            "smart-account",
            "signers",
            "add",
            "--profile",
            PROFILE,
            "--account",
            ACCOUNT,
            "--rule-id",
            "4242424",
            "--signer-delegated",
            delegated.as_str(),
            "--signer-secret-env",
            SECRET_VAR,
        ]
        .map(str::to_owned)
        .to_vec(),
    )
    .await;
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("smart-account signers add: submitting add_signer"),
        "{output:?}"
    );
    let error = error_of(&output);
    assert_eq!(error["code"], "sa.signer_set_missing_baseline", "{error}");
    for text in [&output.stdout, &output.stderr] {
        assert_no_marker_in_text(&String::from_utf8_lossy(text), "4242424");
    }
}

/// The signer and pin verbs log their dispatch events before the manager or
/// the contract checks the rule and the values against the rule. A rule id
/// the account does not hold, a signer id, a threshold, a weight and the
/// batch size stay out of those events and out of the refusals.
#[tokio::test]
#[serial]
async fn signer_verb_events_hold_no_rule_values() {
    const MARKERS: [&str; 4] = ["4242424", "4343434", "4444444", "4545454"];
    let delegated = account_id_for_seed([9; 32]);
    let second = account_id_for_seed([11; 32]);
    let signer = ["--signer-secret-env", SECRET_VAR];
    let cases: [(Vec<&str>, &str, &str); 8] = [
        (
            vec!["signers", "list"],
            "smart-account signers list: querying on-chain signer set",
            "sa.deployment_failed",
        ),
        (
            vec!["signers", "refresh"],
            "smart-account signers refresh: writing fresh baseline",
            "sa.deployment_failed",
        ),
        (
            [
                &["signers", "remove", "--signer-id", "4343434"][..],
                &signer,
            ]
            .concat(),
            "smart-account signers remove: submitting remove_signer",
            "sa.signer_set_missing_baseline",
        ),
        (
            [
                &["signers", "set-threshold", "--new-threshold", "4444444"][..],
                &signer,
            ]
            .concat(),
            "smart-account signers set-threshold: submitting set_threshold",
            "sa.signer_set_missing_baseline",
        ),
        (
            [
                &[
                    "signers",
                    "set-weighted-threshold",
                    "--new-threshold",
                    "4444444",
                ][..],
                &signer,
            ]
            .concat(),
            "smart-account signers set-weighted-threshold: submitting set_threshold",
            "sa.deployment_failed",
        ),
        (
            [
                &["signers", "set-signer-weight", "--new-weight", "4545454"][..],
                &["--signer-delegated", delegated.as_str()],
                &signer,
            ]
            .concat(),
            "smart-account signers set-signer-weight: submitting set_signer_weight",
            "sa.deployment_failed",
        ),
        (
            [
                &["signers", "batch-add"][..],
                &["--signer-delegated", delegated.as_str()],
                &["--signer-delegated", second.as_str()],
                &signer,
            ]
            .concat(),
            "smart-account signers batch-add: submitting batch_add_signer",
            "sa.signer_set_missing_baseline",
        ),
        (
            vec!["rules", "verify-pins"],
            "smart-account rules verify-pins: running",
            "sa.deployment_failed",
        ),
    ];
    for (verb, message, code) in cases {
        let args = [
            &["smart-account"][..],
            &verb[..2],
            &[
                "--profile",
                PROFILE,
                "--account",
                ACCOUNT,
                "--rule-id",
                "4242424",
            ],
            &verb[2..],
        ]
        .concat()
        .into_iter()
        .map(str::to_owned)
        .collect();
        let output = run_against_timelock(
            json!({"error": "HostError: Error(Contract, #3000)", "latestLedger": 1000}),
            args,
        )
        .await;
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(message),
            "missing {message:?}: {output:?}"
        );
        assert_eq!(error_of(&output)["code"], code, "{message}: {output:?}");
        for (stream, text) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
            for marker in MARKERS {
                stellar_agent_test_support::rejected_value::assert_no_marker_in_labeled_text(
                    &format!("{message}: {stream}"),
                    &String::from_utf8_lossy(text),
                    marker,
                );
            }
        }
        // The batch of two signers has a size no marker can hold, so the
        // check names the field.
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("batch_len"),
            "{output:?}"
        );
    }
}

/// The schedule submit event, which runs before the contract checks the
/// delay, holds no delay.
#[test]
#[serial]
fn timelock_schedule_submit_event_holds_no_delay() {
    let home = tempfile::tempdir().expect("home");
    save_profile(home.path(), "http://127.0.0.1:1");
    let output = run(
        home.path(),
        &timelock_args(
            "schedule",
            &[
                "--target",
                ACCOUNT,
                "--function",
                "upgrade",
                "--delay-ledgers",
                "4242424",
            ],
        )
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>(),
        "pretty",
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("smart-account timelock schedule: submitting"),
        "{output:?}"
    );
    assert_eq!(
        error_of(&output)["code"],
        "sa.timelock_schedule_failed",
        "{output:?}"
    );
    for text in [&output.stdout, &output.stderr] {
        assert_no_marker_in_text(&String::from_utf8_lossy(text), "4242424");
    }
}

/// A registry entry whose address fails the C-strkey parse is refused with
/// the fixed text at every adapter, for the WebAuthn and the Ed25519 verifier
/// alike, and an Ed25519 override takes the same text.
#[test]
#[serial]
fn verifier_address_refusals_hold_no_address() {
    const WEBAUTHN: &str = "smart-account operation failed (sa.auth_entry_construction_failed): \
                            verifier registry address must be a valid Stellar C-strkey; repair \
                            the verifier entry in networks.toml";
    const ED25519: &str = "smart-account operation failed (sa.auth_entry_construction_failed): \
                           --signer-ed25519 verifier must be a valid Stellar C-strkey; supply \
                           --verifier or configure the verifier entry in networks.toml";
    let home = tempfile::tempdir().expect("home");
    save_profile(home.path(), "http://127.0.0.1:1");
    let mut registry = VerifierRegistry::open_at(home.path().join("networks.toml")).expect("open");
    registry
        .record_webauthn_verifier(
            TESTNET_PASSPHRASE,
            MARKER.to_owned(),
            WEBAUTHN_VERIFIER_WASM_SHA256.to_owned(),
        )
        .expect("record");
    registry
        .record_ed25519_verifier(
            TESTNET_PASSPHRASE,
            MARKER.to_owned(),
            ED25519_VERIFIER_WASM_SHA256.to_owned(),
        )
        .expect("record");
    registry.persist().expect("persist");

    let pubkey = "ab".repeat(32);
    let deploy = [
        "accounts",
        "deploy-c",
        "--profile",
        PROFILE,
        "--accept-no-delegated-fallback",
        "--deployer-secret-env",
        SECRET_VAR,
        "--salt-random",
    ];
    let add = [
        "smart-account",
        "signers",
        "add",
        "--profile",
        PROFILE,
        "--account",
        ACCOUNT,
        "--rule-id",
        "1",
        "--signer-secret-env",
        SECRET_VAR,
    ];
    let batch = [
        "smart-account",
        "signers",
        "batch-add",
        "--profile",
        PROFILE,
        "--account",
        ACCOUNT,
        "--rule-id",
        "1",
        "--signer-secret-env",
        SECRET_VAR,
    ];
    let webauthn = ["--signer-webauthn", "laptop"];
    let ed25519 = ["--signer-ed25519", pubkey.as_str()];
    let override_flag = ["--verifier", MARKER];
    let cases: [(Vec<&str>, &str); 9] = [
        ([&deploy[..], &webauthn].concat(), WEBAUTHN),
        ([&add[..], &webauthn].concat(), WEBAUTHN),
        ([&batch[..], &webauthn].concat(), WEBAUTHN),
        ([&deploy[..], &ed25519].concat(), ED25519),
        ([&add[..], &ed25519].concat(), ED25519),
        ([&batch[..], &ed25519].concat(), ED25519),
        ([&deploy[..], &ed25519, &override_flag].concat(), ED25519),
        ([&add[..], &ed25519, &override_flag].concat(), ED25519),
        ([&batch[..], &ed25519, &override_flag].concat(), ED25519),
    ];
    for (args, expected) in cases {
        let output = run(home.path(), &args, "pretty");
        let error = error_of(&output);
        assert_eq!(error["message"], expected, "{args:?}");
        for text in [
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ] {
            assert!(!text.contains(MARKER), "{args:?}: {text}");
        }
    }
}

/// An unusable audit log path stays out of the deploy-c failure event in
/// both log formats, and the event keeps its message.
#[test]
#[serial]
fn deploy_c_audit_event_holds_no_path() {
    let home = tempfile::tempdir().expect("home");
    let audit_log = home.path().join(MARKER);
    std::fs::create_dir(&audit_log).expect("directory at the audit path");
    save_profile_with_audit_log(home.path(), "http://127.0.0.1:1", &audit_log);
    let signer = stellar_strkey::ed25519::PublicKey([1; 32]).to_string();
    for log_format in ["pretty", "json"] {
        let output = run(
            home.path(),
            &[
                "accounts",
                "deploy-c",
                "--profile",
                PROFILE,
                "--initial-signer",
                signer.as_str(),
                "--deployer-secret-env",
                SECRET_VAR,
                "--salt-random",
            ],
            log_format,
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("deploy-c audit writer open failed"),
            "{log_format}: {stderr}"
        );
        assert!(!stderr.contains(MARKER), "{log_format}: {stderr}");
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains(MARKER),
            "{log_format}"
        );
    }
}
