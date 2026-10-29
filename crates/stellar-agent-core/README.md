# stellar-agent-core

See [Mainnet configurations and scope](../../docs/getting-started.md#mainnet-configurations-and-scope)
for build configuration, admitted operations, and exclusions.

Core library for the stellar-agent-wallet: signing, policy engine, smart accounts, and a hash-chained audit log.

This is the primary public API of the workspace and the wallet's mostly synchronous layer; it creates no async runtime of its own. It provides typed amounts (`StellarAmount`), the error taxonomy (`WalletError`), the JSON envelope (`Envelope`), observability primitives, smart-account auth-digest and context-rule-ID helpers, per-profile configuration, and the policy and proof types for mainnet authorization. Wallet unlock and seed access are synchronous. `rpc_budget::bound_stage` is async and requires a Tokio runtime.

External consumers embed this crate alongside `stellar-agent-network` to sign and submit transactions without spawning the CLI subprocess; see `examples/embed/` in the repository for a complete walkthrough. Network transport, transaction assembly, and signing live in `stellar-agent-network`.

It is part of the stellar-agent-wallet workspace and backs the `stellar-agent-cli` and `stellar-agent-mcp` binaries.

Core verifies policy and provides sealed proof facts. Network consumers
independently check authorization at signing and submission. A verified policy
alone grants no signing authority.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
