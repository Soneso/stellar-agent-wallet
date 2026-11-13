//! Test-only observations of process initialization and tool registration.

/// Appends an observation to the configured test trace, ignoring unavailable files.
/// Without `test-helpers`, this function does nothing.
pub fn record(_observation: &str) {
    #[cfg(feature = "test-helpers")]
    {
        use std::io::Write;

        if let Some(path) = std::env::var_os("STELLAR_AGENT_TEST_INIT_TRACE")
            && let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
        {
            let _ = writeln!(file, "{_observation}");
        }
    }
}
