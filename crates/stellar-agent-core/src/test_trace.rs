//! Test-only observations of process initialization and tool registration.

/// Appends an observation to the configured test trace, ignoring unavailable files.
/// Without `test-helpers`, this function does nothing.
pub fn record(_observation: &str) {
    #[cfg(feature = "test-helpers")]
    {
        use std::io::Write;

        if let Some(path) =
            crate::profile::schema::sandboxed_override("STELLAR_AGENT_TEST_INIT_TRACE")
            && let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
        {
            let _ = writeln!(file, "{_observation}");
        }
    }
}

#[cfg(all(test, feature = "test-helpers"))]
mod tests {
    #![allow(clippy::unwrap_used, reason = "fixture assertions")]

    #[test]
    #[serial_test::serial]
    fn trace_override_outside_a_sandbox_is_ignored() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("trace");
        let _trace = stellar_agent_test_support::env_guard::ScopedEnvVar::new(
            "STELLAR_AGENT_TEST_INIT_TRACE",
            Some(path.as_os_str()),
        );
        super::record("unmarked");
        assert!(!path.exists(), "an unmarked trace must not be created");
        std::fs::write(&path, "existing\n").unwrap();
        super::record("unmarked");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "existing\n");
        stellar_agent_test_support::sandbox::mark_sandbox(temporary.path()).unwrap();
        super::record("marked");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "existing\nmarked\n"
        );
    }
}
