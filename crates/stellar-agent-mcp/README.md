# stellar-agent-mcp

Model Context Protocol (MCP) stdio server for the stellar-agent-wallet.

`stellar-agent-mcp` exposes the agent wallet's capabilities as MCP tools over a stdio transport, so an MCP-capable agent host can drive balances, payments, signing, DeFi verbs, SEP flows, and toolsets through a policy-gated interface. Tools are registered at link time: `#[mcp_tool_item(...)]` annotations emit `McpToolRegistration` records that the `inventory` crate collects, and the server iterates them at startup to build the descriptor map consumed by the policy engine.

## Install

```
cargo install stellar-agent-mcp
```

## Usage

The binary starts the server process and speaks MCP JSON-RPC over stdio to a host such as the Claude Desktop app or another MCP client. For configuration, the tool catalogue, and integration walkthroughs, see the workspace README and the `docs/` directory in the repository.

## Status

Pre-release alpha. APIs and the tool surface may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
