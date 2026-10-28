//! Compile-time build reporting for the `mainnet-write` Cargo feature, which is
//! disabled by default.
//!
//! The network, CLI, and MCP features of the same name forward to this one, and
//! together they gate the authorized mainnet write paths. Cargo unifies features
//! per build, so a crate that enables `mainnet-write` on core turns the marker on
//! for every crate linked against that core.

/// Version-output line for a build with the `mainnet-write` feature enabled.
#[cfg(feature = "mainnet-write")]
pub const MAINNET_WRITE_MARKER: &str = "STELLAR_AGENT_BUILD_MAINNET_WRITE=on";

/// Version-output line for a build with the `mainnet-write` feature disabled.
#[cfg(not(feature = "mainnet-write"))]
pub const MAINNET_WRITE_MARKER: &str = "STELLAR_AGENT_BUILD_MAINNET_WRITE=off";

/// Whether this core instance has the `mainnet-write` feature enabled.
#[cfg(feature = "mainnet-write")]
pub const MAINNET_WRITE: bool = true;

/// Whether this core instance has the `mainnet-write` feature enabled.
#[cfg(not(feature = "mainnet-write"))]
pub const MAINNET_WRITE: bool = false;

#[cfg(test)]
mod tests {
    use super::{MAINNET_WRITE, MAINNET_WRITE_MARKER};

    #[test]
    fn marker_matches_feature() {
        let suffix = if cfg!(feature = "mainnet-write") {
            "on"
        } else {
            "off"
        };
        let expected = format!("{}{}{}", "STELLAR_AGENT_BUILD_", "MAINNET_WRITE=", suffix);
        assert_eq!(MAINNET_WRITE_MARKER, expected);
    }

    #[test]
    fn boolean_matches_feature() {
        assert_eq!(MAINNET_WRITE, cfg!(feature = "mainnet-write"));
    }
}
