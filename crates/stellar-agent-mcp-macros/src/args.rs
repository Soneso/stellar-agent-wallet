//! Attribute argument parsers for the `#[mcp_tool_item(...)]` annotation.
//!
//! This module is compile-time only — it lives entirely inside the proc-macro
//! crate and is not exported.  The runtime registry struct (`McpToolRegistration`)
//! lives in `stellar_agent_core::policy` so that non-proc-macro crates can
//! reference it without depending on this proc-macro crate.
//!
//! # Trust boundary
//!
//! This module is compile-time host-privileged code.  It contains no `unsafe`,
//! no env-var reads, no filesystem reads, no network access, no `extern "C"`,
//! and no `#[link]` attributes.

use darling::FromMeta;

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time argument parser (proc-macro side only)
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed arguments for the `#[mcp_tool_item(...)]` annotation on an individual
/// tool fn inside an `#[mcp_tool_router]` impl block.
///
/// Parsed by `darling::FromMeta` from the attribute token stream.  All fields
/// are required; omitting any field is a compile-time error.
///
/// # Fields
///
/// | Field | Type | Description |
/// |-------|------|-------------|
/// | `name` | `String` | The registered MCP tool name — must match the sibling `#[tool(name = "...")]`. |
/// | `destructive_hint` | `bool` | Whether the tool modifies chain state. Must match `#[tool(annotations(destructive_hint = ...))]`. |
/// | `read_only_hint` | `bool` | Whether the tool is purely read-only. Must match `#[tool(annotations(read_only_hint = ...))]`. |
/// | `chain_id_required` | `bool` | Whether the tool requires a CAIP-2 `chain_id` argument. |
#[derive(Debug, FromMeta)]
pub(crate) struct McpToolItemArgs {
    /// The registered MCP tool name.
    pub name: String,
    /// Whether the tool carries `destructiveHint: true`.
    pub destructive_hint: bool,
    /// Whether the tool carries `readOnlyHint: true`.
    pub read_only_hint: bool,
    /// Whether the tool requires a CAIP-2 `chain_id` argument.
    pub chain_id_required: bool,
}
