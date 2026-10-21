//! Compile-time feature state for wallet build reporting.
//!
//! The `mainnet-write` Cargo feature is disabled by default and changes build
//! reporting only. Cargo unifies features per build, so a crate that enables
//! `mainnet-write` on core turns the marker on for every crate linked against
//! that core.

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
        let expected = if cfg!(feature = "mainnet-write") {
            "STELLAR_AGENT_BUILD_MAINNET_WRITE=on"
        } else {
            "STELLAR_AGENT_BUILD_MAINNET_WRITE=off"
        };
        assert_eq!(MAINNET_WRITE_MARKER, expected);
    }

    #[test]
    fn boolean_matches_feature() {
        assert_eq!(MAINNET_WRITE, cfg!(feature = "mainnet-write"));
    }
}
