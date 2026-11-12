//! Source contracts of the suites that use the shared child-process driver,
//! of the halt fixture, and of the shutdown documentation.
//!
//! Each test reads files of this crate or the workspace at test time and
//! checks the text they must hold.

#![allow(
    clippy::panic,
    reason = "test checks; an unreadable file fails the calling test"
)]

/// A file of this crate or the workspace, read at test time.
fn read(relative: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} must be readable: {error}", path.display()))
}

const HALT: &str = "tests/mcp/halt_integration.rs";
const INTEGRATION: &str = "tests/mcp/integration.rs";
const PROFILE_SELECTION: &str = "tests/mcp/profile_selection_integration.rs";

/// The tests each migrated suite runs on Unix.
const MIGRATED_TESTS: [(&str, &[&str]); 3] = [
    (
        HALT,
        &[
            "every_tool_that_is_not_read_only_refuses_while_halted_without_signer_or_rpc",
            "read_only_tools_and_the_profile_resource_answer_while_halted",
            "a_halt_lifted_on_a_running_server_lets_the_next_call_reach_the_policy_gate",
            "a_halt_set_on_a_running_server_refuses_the_next_call",
            "an_unreadable_marker_refuses_without_a_signer_read",
            "the_signer_read_and_request_witnesses_count_an_unhalted_call",
            "serve_on_until_returns_after_the_shutdown_future_resolves",
            "serve_on_until_returns_after_the_shutdown_wait_when_the_session_cannot_stop",
            "the_server_drains_a_queued_halt_row_when_its_stdin_closes",
            "the_server_drains_a_queued_halt_row_on_sigterm",
        ],
    ),
    (
        INTEGRATION,
        &[
            "initialize_returns_capabilities",
            "notifications_initialized_processed",
            "tools_list_includes_stellar_balances",
            "tools_call_stellar_balances_unknown_account_returns_tool_error",
            "tools_call_stellar_balances_invalid_strkey_returns_invalid_params",
            "tools_call_unknown_tool_returns_error",
            "policy_engine_allows_stellar_balances_read_only",
            "decision_allow_propagates",
        ],
    ),
    (
        PROFILE_SELECTION,
        &[
            "profile_flag_serves_the_named_profile",
            "profile_equals_form_serves_the_named_profile",
            "environment_variable_selects_the_profile_file",
            "profile_flag_beats_the_environment_variable",
            "no_name_and_no_profile_file_falls_back_to_the_synthesised_testnet_profile",
            "named_but_missing_profile_refuses_instead_of_falling_back",
            "a_seed_as_a_missing_profile_name_is_not_printed_on_stderr",
            "environment_named_but_missing_profile_refuses_instead_of_falling_back",
            "explicitly_named_default_profile_refuses_when_absent",
            "traversal_profile_name_is_refused",
            "windows_reserved_device_profile_name_is_refused",
            "leading_dash_profile_name_is_refused",
            "unknown_flag_is_refused",
            "help_documents_profile_selection",
            "noop_profile_copied_from_another_profile_refuses_to_serve_under_the_new_name",
            "profile_without_a_derivable_owner_key_name_refuses",
            "environment_variable_never_selects_a_mainnet_profile",
            "profile_flag_serves_a_mainnet_profile",
            "a_mainnet_default_profile_needs_the_flag",
            "trust_root_environment_overlays_refuse_startup_on_testnet",
            "protected_environment_overlay_reports_wire_code",
            "provider_attestation_refusal_reports_wire_code",
            "shared_key_entry_refuses_mainnet_startup_with_its_wire_code",
            "shared_key_entry_warns_and_testnet_startup_answers_initialize",
            "startup_diagnostics_omit_shared_scope_and_owner_parts",
            "an_invalid_profile_name_is_not_printed_on_stderr",
            "profile_selection_refusal_logs_omit_credential_markers",
            "profile_selection_mismatch_omits_loaded_and_refusal_names",
            "profile_selection_mainnet_env_refusal_omits_the_requested_name",
        ],
    ),
];

/// `run_with_initialize` as the refusal tests depend on it.
const RUN_WITH_INITIALIZE: &str = r####"fn run_with_initialize(mut command: Command) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("stellar-agent-mcp binary must spawn");
    {
        let mut stdin = child.stdin.take().expect("child stdin must be piped");
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2024-11-05","capabilities":{{}},"clientInfo":{{"name":"test-client","version":"0.1.0"}}}}}}"#
        )
        .unwrap_or_else(|error| {
            // A refusing server exits before reading stdin.
            if error.kind() != std::io::ErrorKind::BrokenPipe {
                panic!("write to child stdin must succeed: {error:?}");
            }
        });
    }
    child.wait_with_output().expect("child must exit")
}"####;

/// The three suites drive the binary through the shared driver. None
/// declares a driver of its own or reads a response line without a deadline.
/// Each listed test appears once, and the initialization helper matches the
/// expected source.
#[test]
fn shared_driver_replaces_three_helpers_and_preserves_test_inventory() {
    for (file, structure) in [
        (HALT, "struct ChildServer"),
        (INTEGRATION, "struct McpDriver"),
        (PROFILE_SELECTION, "struct McpSession"),
    ] {
        let source = read(file);
        assert_eq!(source.matches(structure).count(), 0, "{file}: {structure}");
        assert_eq!(
            source.matches(".read_line(").count(),
            0,
            "{file} reads no response line without a deadline"
        );
        assert!(
            source.contains("ChildDriver"),
            "{file} drives the binary through the shared driver"
        );
    }
    for (file, tests) in MIGRATED_TESTS {
        let source = read(file);
        for test in tests {
            assert_eq!(
                source.matches(&format!("fn {test}()")).count(),
                1,
                "{file} keeps {test}"
            );
        }
    }
    let profile_selection = read(PROFILE_SELECTION);
    assert_eq!(
        profile_selection.matches(RUN_WITH_INITIALIZE).count(),
        1,
        "run_with_initialize matches the expected source"
    );
}

/// The halt fixture is named for the data root it holds, installs its store
/// through the restoring guard, and the manifest says what the headless
/// dependency's `test-helpers` feature does.
#[test]
fn halt_fixture_names_its_home_and_explains_test_helpers() {
    let halt = read(HALT);
    assert_eq!(halt.matches("HeadlessServer").count(), 0);
    assert_eq!(
        halt.matches("keyring_core::set_default_store(").count(),
        0,
        "the halt suite installs no default store directly"
    );
    assert!(halt.contains("struct HeadlessHome"));
    assert!(halt.contains("DefaultStoreGuard::install("));

    let manifest = read("Cargo.toml");
    assert_eq!(manifest.matches("STELLAR_AGENT_HOME").count(), 2);
    let explanation = manifest
        .lines()
        .find(|line| line.contains("headless-keyring/store.keyring"))
        .expect("the manifest names the store file the child resolves");
    assert!(explanation.starts_with('#'), "{explanation}");
    assert!(explanation.contains("test-helpers"), "{explanation}");
    assert_eq!(
        explanation.matches("STELLAR_AGENT_HOME").count(),
        1,
        "{explanation}"
    );
}

/// The shutdown descriptions name the Windows events, exit code 3 on a
/// second event, the two-second mutex bound with its scope, and the recovery
/// of queued rows.
#[test]
fn shutdown_documentation_names_events_limits_and_queued_recovery() {
    let mcp = read("../../docs/mcp.md");
    let governance = read("../../docs/cli-reference/profile-and-governance.md");
    let skill = read("../../skills/stellar-agent-wallet/references/approvals-and-audit.md");
    for (name, text) in [
        ("docs/mcp.md", &mcp),
        ("docs/cli-reference/profile-and-governance.md", &governance),
        ("approvals-and-audit.md", &skill),
    ] {
        for required in [
            "SIGINT",
            "SIGTERM",
            "Ctrl-Break",
            "console close",
            "exit code 3",
            "two seconds",
            "mutex",
            "next draining writer",
        ] {
            assert!(text.contains(required), "{name} must state {required:?}");
        }
    }
    assert!(
        mcp.contains("filesystem and keyring work"),
        "docs/mcp.md states the scope of the bound"
    );

    let manifest = read("Cargo.toml");
    let tokio_comment: String = manifest
        .lines()
        .skip_while(|line| !line.starts_with("# Tokio async runtime"))
        .take_while(|line| line.starts_with('#'))
        .map(|line| line.trim_start_matches('#').trim())
        .collect::<Vec<_>>()
        .join(" ");
    for required in ["SIGINT", "SIGTERM", "Ctrl-Break", "console close", "code 3"] {
        assert!(
            tokio_comment.contains(required),
            "the tokio dependency comment states {required:?}: {tokio_comment}"
        );
    }

    let main = read("src/main.rs");
    let step_seven: String = main
        .lines()
        .skip_while(|line| !line.contains("7. Drain the audit outboxes"))
        .take_while(|line| line.trim_start().starts_with("//"))
        .map(|line| line.trim_start().trim_start_matches('/').trim())
        .collect::<Vec<_>>()
        .join(" ");
    for required in [
        "Ctrl-Break",
        "console close",
        "two seconds",
        "mutex wait only",
        "code 3",
    ] {
        assert!(
            step_seven.contains(required),
            "the exit-drain comment states {required:?}: {step_seven}"
        );
    }
}
