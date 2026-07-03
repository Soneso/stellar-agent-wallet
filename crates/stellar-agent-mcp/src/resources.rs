//! MCP resource content generators for the Stellar agent wallet.
//!
//! Currently exposes `usage_md_content()` which is served as the
//! `mcp-resource://usage.md` resource by the `ServerHandler` impl in
//! `server.rs`.  The resource is also scanned by the
//! `resource_no_secrets.rs` integration test.

// ─────────────────────────────────────────────────────────────────────────────
// MCP resource content generators
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the content of the `mcp-resource://usage.md` resource.
///
/// This function is also called by the `resource_no_secrets` integration test
/// to verify that resource output contains no secret-shaped bytes.
pub fn usage_md_content() -> String {
    String::from(include_str!("../docs/usage.md"))
}
