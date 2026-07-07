# stellar-agent-mcp-macros

Internal support crate for the stellar-agent-wallet.

This proc-macro crate exports the `#[mcp_tool_router]` attribute macro (applied to the same `impl` block as rmcp's `#[tool_router]`) and the `#[mcp_tool_item]` marker. `#[mcp_tool_router]` scans the impl block for functions carrying `#[mcp_tool_item(...)]` annotations, strips those markers so the compiler does not see unknown attributes, and emits `inventory::submit!` registry items that the `inventory` crate collects at link time. This is how the MCP server builds its tool-descriptor map.

It is published as part of the stellar-agent-wallet workspace to complete the dependency graph on crates.io and is not designed for standalone use; it is consumed only by `stellar-agent-mcp`.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
