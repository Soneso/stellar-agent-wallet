//! Stellar agent wallet MCP server library.
//!
//! Re-exports the server module for integration-test access.  The `main.rs`
//! binary entry point re-uses this crate's logic; integration tests (in
//! `tests/`) import from `stellar_agent_mcp::*` directly.
//!
//! # Module layout
//!
//! - [`server`] — `WalletServer` struct, `new()`, `ServerHandler` impl, and
//!   back-compat re-exports for all public argument types and resource helpers.
//! - [`transport`] — `BoundedStdioTransport` and the `run()` async entry point.
//! - `resources` — MCP resource content generators (`usage_md_content`).
//! - `tools` — per-family tool implementations (see `tools/mod.rs` for the
//!   authoritative family list); e.g. `tools::balances`, `tools::pay`,
//!   `tools::sep43_*`, `tools::x402_*`, `tools::toolsets`, and others.
//!   `tools::common` provides shared constants, `ToolCatalogueAdapter`,
//!   dispatch helpers, and `build_tool_registry`.
//!
//! # Tool registry
//!
//! Tool registration metadata is emitted by `#[mcp_tool_item(...)]` annotations
//! on each tool fn inside the `#[mcp_tool_router]` + `#[tool_router]` impl block.
//! The `inventory` crate collects `McpToolRegistration` records at link time;
//! `WalletServer::new` iterates `inventory::iter::<McpToolRegistration>()` to
//! build the descriptor map consumed by `PolicyEngine::evaluate`.
//!
//! # Primary consumers
//!
//! - `main.rs` — binary entry point that starts the server process.
//! - `tests/resource_no_secrets.rs` — verifies resource generator output
//!   contains no secret-shaped bytes (runtime gate).
//! - `tests/integration.rs` — end-to-end MCP JSON-RPC protocol tests.
//! - `tests/registry_walk.rs` — inventory registry ↔ rmcp ToolRouter parity
//!   test.

#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Maximum line length accepted by the MCP JSON-RPC codec (1 MiB).
///
/// Mitigation for the `rmcp` default `usize::MAX` line-length DoS surface.
pub const STELLAR_AGENT_MCP_MAX_LINE_BYTES: usize = 1024 * 1024;

/// MCP resource content generators (usage.md).
///
/// Crate-internal: external consumers reach `usage_md_content` via the
/// `pub use` re-export in [`server`].
pub(crate) mod resources;

/// MCP server handler, tool registry, and `WalletServer` construction.
pub mod server;

/// Bounded stdio transport and server startup (`run` fn).
///
/// Public so the binary `main.rs` can call `transport::run(profile)`.
pub mod transport;

/// Bridges `stellar_agent_network::AccountView` to the
/// `stellar_agent_core::policy::v1::AccountReservesView` trait.
///
/// Public so per-tool dispatch sites can construct [`policy_adapter::AccountViewAdapter`]
/// when populating `EvalContext.account_view`.  Per-tool wiring is deferred.
pub mod policy_adapter;

/// MCP tool implementations organised by tool family.
///
/// Crate-internal: every public type defined here is re-exported by
/// [`server`] via `pub use crate::tools::<family>::...` for back-compat with
/// existing tests that import via `stellar_agent_mcp::server::*`.
pub(crate) mod tools;
