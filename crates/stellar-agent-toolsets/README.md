# stellar-agent-toolsets

Signed-toolset format parsing and capability-manifest validation for the stellar-agent-wallet.

This crate parses and validates a toolset directory's `TOOLSET.md` and the wallet capability manifest carried in its frontmatter metadata, producing either a validated, typed `Toolset` value or a typed refusal. It also provides the pre-canonicalisation argument-validation guard `validate_toolset_tool_args` (with its depth, node-count, and key-denylist constants), which both the MCP dispatcher and the CLI execution path call before deserializing typed arguments.

This crate is the format and parse/validate substrate only. It performs no install, no signing, no runtime enforcement, no MCP or CLI registration, and no network I/O; those concerns live in the install and runtime toolset crates.

It is part of the stellar-agent-wallet workspace and is consumed by the toolset install and runtime layers rather than directly by most users.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
