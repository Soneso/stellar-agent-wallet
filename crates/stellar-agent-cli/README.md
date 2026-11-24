# stellar-agent-cli

Command-line binary for the stellar-agent-wallet.

`stellar-agent` is the CLI for an agent-operated Stellar wallet: signing, policy evaluation, smart accounts, approvals, DeFi verbs, and a hash-chained audit log. It installs as `stellar-agent` on your PATH and is also discovered as `stellar agent ...` by the incumbent `stellar-cli` through the external-binary plugin convention.

## Install

```
cargo install --locked stellar-agent-cli@0.1.0-alpha.13
```

`--locked` makes cargo build with the `Cargo.lock` published in the crate. The
version is spelled out because a bare crate name matches stable versions only.

The same executable runs the MCP server as `stellar-agent mcp serve`, and when
it runs under the file name `stellar-agent-mcp`. For MCP clients that start that
name, copy the executable:

```
cp ~/.cargo/bin/stellar-agent ~/.cargo/bin/stellar-agent-mcp
```

## Usage

Run `stellar-agent --help` for the authoritative subcommand list. For setup, configuration, and end-to-end walkthroughs, see the workspace README and the `docs/` directory in the repository.

## Status

Pre-release alpha. APIs and command surface may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
