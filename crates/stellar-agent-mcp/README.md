# stellar-agent-mcp

Model Context Protocol (MCP) stdio server library for the stellar-agent-wallet.

`stellar-agent-mcp` exposes the wallet's capabilities as MCP tools over stdio. An MCP client can read balances, send payments, sign payloads, run DeFi and SEP flows, and invoke toolsets through a policy-gated interface. Tools register at link time through the `#[mcp_tool_item(...)]` attribute. At startup the server builds the descriptor map the policy engine consumes from those registrations.

This crate is a library with no executable. The `stellar-agent` executable of the `stellar-agent-cli` crate runs it.

## Install

Install the `stellar-agent-cli` package:

```
cargo install --locked stellar-agent-cli@0.1.0-alpha.13
```

`--locked` makes cargo build with the `Cargo.lock` published in the crate. The
version is spelled out because a bare crate name matches stable versions only.

## Usage

`stellar-agent mcp serve` starts the server process, and so does the executable when it runs under the file name `stellar-agent-mcp`. The server speaks MCP JSON-RPC over stdio to a host such as the Claude Desktop app or another MCP client. For clients configured with `stellar-agent-mcp`, copy the executable:

```
cp ~/.cargo/bin/stellar-agent ~/.cargo/bin/stellar-agent-mcp
```

For configuration, the tool catalog, and integration walkthroughs, see the workspace README and the `docs/` directory in the repository.

## Status

Pre-release alpha. APIs and the tool surface may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
