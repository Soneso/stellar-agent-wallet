//! The capture isolation regression. It lives in the CLI binary, which holds
//! the fragment tests it spawns.

use super::test_support::{CHILD, EnvGuard, child_command};

/// Fragment captures exclude parent overlays while the serial lock is held.
#[test]
#[serial_test::serial]
fn capture_isolates_profile_environment() -> Result<(), Box<dyn std::error::Error>> {
    for (var, value) in [
        ("STELLAR_AGENT_RPC_URL", "overlay-rpc"),
        (
            "STELLAR_AGENT_MCP_SIGNER_DEFAULT",
            "{ service = \"overlay\", account = \"overlay\" }",
        ),
    ] {
        let _parent = EnvGuard::set(var.to_owned(), value);
        // The outer tests receive the poison explicitly; each capture must
        // exclude it before running the fragment operation in its own child.
        let output = child_command(
            "commands::profile::apply_fragment::tests::",
            &[(var, value)],
        )
        .env_remove(CHILD)
        .output()?;
        let stdout = String::from_utf8(output.stdout)?;
        let stderr = String::from_utf8(output.stderr)?;
        assert!(output.status.success(), "{var}: {stdout}\n{stderr}");
        assert!(stdout.contains("4 passed"), "{var}: {stdout}");
    }
    Ok(())
}
