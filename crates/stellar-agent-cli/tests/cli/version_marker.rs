//! Version output reports the binary package version and compiled feature state.

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "test assertions require a running binary"
)]
mod tests {
    use std::process::Command;

    fn assert_version(flag: &str) {
        let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
            .arg(flag)
            .output()
            .expect("CLI binary runs");
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
            format!("stellar-agent {}\n{expected}\n", env!("CARGO_PKG_VERSION")),
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
}
