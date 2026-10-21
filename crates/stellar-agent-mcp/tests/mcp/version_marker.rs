//! Version output reports build state separately from the MCP help header.

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "test assertions require a running binary"
)]
mod tests {
    use std::process::Command;

    fn assert_version(flag: &str) {
        let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent-mcp"))
            .arg(flag)
            .output()
            .expect("MCP binary runs");
        assert!(output.status.success(), "{flag}: {:?}", output.status);
        assert!(output.stderr.is_empty(), "{flag}: {:?}", output.stderr);
        let stdout = String::from_utf8(output.stdout).expect("version output is UTF-8");
        let expected = if cfg!(feature = "mainnet-write") {
            "STELLAR_AGENT_BUILD_MAINNET_WRITE=on"
        } else {
            "STELLAR_AGENT_BUILD_MAINNET_WRITE=off"
        };
        assert_eq!(
            stdout,
            format!(
                "stellar-agent-mcp {}\n{expected}\n",
                env!("CARGO_PKG_VERSION")
            ),
            "{flag}"
        );
    }

    #[test]
    fn long_version_reports_build_state() {
        assert_version("--version");
    }

    #[test]
    fn short_version_reports_build_state() {
        assert_version("-V");
    }

    #[test]
    fn help_keeps_package_version_without_marker() {
        let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent-mcp"))
            .arg("--help")
            .output()
            .expect("MCP binary runs");
        assert!(output.status.success(), "{:?}", output.status);
        assert!(output.stderr.is_empty(), "{:?}", output.stderr);
        let stdout = String::from_utf8(output.stdout).expect("help output is UTF-8");
        assert_eq!(
            stdout.lines().next(),
            Some(format!("stellar-agent-mcp {}", env!("CARGO_PKG_VERSION")).as_str())
        );
        assert!(!stdout.contains("STELLAR_AGENT_BUILD_MAINNET_WRITE="));
    }
}
