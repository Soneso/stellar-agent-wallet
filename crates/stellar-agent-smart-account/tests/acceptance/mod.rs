//! Shared offline precondition for acceptance tests that start the isolated CLI.

use std::path::PathBuf;

/// Requires a readable CLI with the storage isolation marker before network use.
///
/// # Panics
/// Panics with the build command when the file is missing, unreadable, or unisolated.
pub fn require_acceptance_binary(path: PathBuf) -> PathBuf {
    stellar_agent_test_support::sandbox::require_isolated_executable(&path).unwrap_or_else(|error| {
        panic!(
            "isolated acceptance binary required at {}: {error} ({:?}). Build with: cargo build --locked --release -p stellar-agent-cli --bin stellar-agent --no-default-features --features test-helpers --features stellar-agent-network/test-helpers (use mainnet-write,test-helpers for the on state)",
            path.display(), error.kind()
        )
    });
    path
}

#[test]
#[should_panic(
    expected = "(NotFound). Build with: cargo build --locked --release -p stellar-agent-cli --bin stellar-agent --no-default-features --features test-helpers --features stellar-agent-network/test-helpers (use mainnet-write,test-helpers for the on state)"
)]
fn required_binary_missing() {
    let dir = tempfile::tempdir().unwrap();
    require_acceptance_binary(dir.path().join("missing"));
}

#[test]
#[should_panic(
    expected = "(IsADirectory). Build with: cargo build --locked --release -p stellar-agent-cli --bin stellar-agent --no-default-features --features test-helpers --features stellar-agent-network/test-helpers (use mainnet-write,test-helpers for the on state)"
)]
fn required_binary_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    require_acceptance_binary(dir.path().to_path_buf());
}

#[test]
#[should_panic(
    expected = "Build the child with test-helpers and stellar-agent-core/test-helpers before running acceptance. (Other). Build with: cargo build --locked --release -p stellar-agent-cli --bin stellar-agent --no-default-features --features test-helpers --features stellar-agent-network/test-helpers (use mainnet-write,test-helpers for the on state)"
)]
fn required_binary_without_marker() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), b"production binary").unwrap();
    require_acceptance_binary(file.path().to_path_buf());
}

#[test]
fn required_binary_with_marker() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        file.path(),
        b"prefix STELLAR_AGENT_TEST_STORAGE_ISOLATED suffix",
    )
    .unwrap();
    assert_eq!(
        require_acceptance_binary(file.path().to_path_buf()),
        file.path()
    );
}

// Compile the child call sites into this offline check, without invoking them.
// Signing children need a secondary RPC endpoint in their empty sandbox profile.
#[test]
fn required_binary_children_use_sandboxes() {
    for (source, tests) in [
        (
            include_str!("../smart_account_caps_testnet_acceptance.rs"),
            &[
                ("h1_16th_signer_refused", true),
                ("h2_6th_policy_refused", true),
            ][..],
        ),
        (
            include_str!("../smart_account_list_rules_testnet_acceptance.rs"),
            &[("h3_cli_envelope_shape_on_testnet", false)][..],
        ),
        (
            include_str!("../smart_account_session_rule_horizon_testnet_acceptance.rs"),
            &[
                ("h_a_install_horizon_exceeded", true),
                ("h_b_update_horizon_exceeded", true),
            ][..],
        ),
    ] {
        for (test, signs) in tests {
            let body = source
                .split_once(&format!("async fn {test}() {{\n"))
                .unwrap()
                .1
                .split_once("\n}")
                .unwrap()
                .0;
            assert!(
                body.contains("let sandbox = StateSandbox::new().expect(\"CLI sandbox\");"),
                "{test}: child needs an owned sandbox"
            );
            assert_eq!(body.matches(".output()").count(), 1, "{test}: child count");
            assert!(
                body.contains("cli_child::cli_command(&binary, sandbox.path())"),
                "{test}: child needs the sandbox environment"
            );
            assert!(!body.contains("Command::new"), "{test}: unfiltered child");
            if *signs {
                let args = body
                    .split_once("cli_child::cli_command(&binary, sandbox.path())")
                    .unwrap()
                    .1
                    .split_once(".args([")
                    .unwrap()
                    .1
                    .split_once("])")
                    .unwrap()
                    .0
                    .split_whitespace()
                    .collect::<String>();
                assert!(
                    args.contains(
                        "\"--secondary-rpc-url\",stellar_agent_test_support::testnet_secondary_rpc_url(),"
                    ),
                    "{test}: signing child needs the testnet secondary RPC endpoint"
                );
            }
        }
    }
}
