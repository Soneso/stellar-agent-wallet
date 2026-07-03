//! Toolset format parsing and capability-manifest validation.
//!
//! ## What this crate does
//!
//! Parses and validates a toolset directory's `TOOLSET.md` (agentskills format)
//! and the wallet capability manifest carried in the frontmatter `metadata`
//! map.  The result is either a validated, typed [`Toolset`] value or a typed
//! [`ToolsetFormatError`] refusal.
//!
//! This crate also provides the pre-canonicalisation argument validation guard
//! [`validate_toolset_tool_args`], which must be called at BOTH toolset dispatch
//! sites before `serde_json::from_value::<TypedArgs>`.  The guard and its
//! constants ([`TOOLSET_ARGS_MAX_DEPTH`], [`TOOLSET_ARGS_MAX_NODES`],
//! [`ARGS_KEY_DENYLIST`]) are defined here so both the MCP dispatcher and the
//! CLI execution path can consume them without an MCP dependency.
//!
//! This crate is the FORMAT + PARSE/VALIDATE substrate only.  It performs no
//! install, no signing, no runtime enforcement, no MCP/CLI registration, and no
//! network I/O.
//!
//! ## Primary consumers
//!
//! - Toolset install/uninstall components — call [`parse_toolset`] before verifying
//!   the publisher key.
//! - Capability enforcement and MCP/CLI registration — consume the
//!   [`CapabilitySet`] and [`Toolset::allowed_tools`] produced here.
//! - MCP dispatcher — calls [`validate_toolset_tool_args`] at both ungated and
//!   gated dispatch sites.
//!
//! ## What this crate does NOT do
//!
//! - Install, uninstall, tarball handling, or publisher-signature verification.
//! - Runtime capability enforcement against agent tool invocations.
//! - First-invoke gate or attestation gate.
//! - Executable `scripts/` execution or sandboxing.
//!
//! ## Sibling crates
//!
//! - `stellar-agent-core` — profile management, policy engine, audit log.
//! - `stellar-agent-network` — RPC transport, signing, keyring storage.
//! - `stellar-agent-mcp` — MCP dispatcher that calls [`validate_toolset_tool_args`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod args_error;
pub mod capability;
pub mod error;
pub mod parse;
pub mod sanitise;
pub mod validate;

pub use args_error::ToolsetArgsError;
pub use capability::{Capability, CapabilitySet};
pub use error::ToolsetFormatError;
pub use parse::{Toolset, parse_toolset};
pub use sanitise::sanitise_display;
pub use validate::{
    ARGS_KEY_DENYLIST, TOOLSET_ARGS_MAX_DEPTH, TOOLSET_ARGS_MAX_NODES, validate_toolset_tool_args,
};

/// Public test-helper for parsing a capability value string into a
/// [`CapabilitySet`].
///
/// Only available under `#[cfg(any(test, feature = "test-helpers"))]`.
/// Sibling crates use this in tests to build `CapabilitySet` values without
/// depending on internal crate details.
#[cfg(any(test, feature = "test-helpers"))]
pub use capability::parse_capability_value_pub;
