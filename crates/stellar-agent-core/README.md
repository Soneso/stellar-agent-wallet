# stellar-agent-core

Core library for the stellar-agent-wallet: signing, policy engine, smart accounts, and a hash-chained audit log.

This is the primary public API of the workspace and the synchronous, runtime-free layer of the wallet. It provides typed amounts (`StellarAmount`), the error taxonomy (`WalletError`), the JSON envelope (`Envelope`), observability primitives, smart-account auth-digest and context-rule-ID helpers, per-profile configuration, and the mainnet write-tools policy gate. All APIs are synchronous except `Wallet::unlock`, which is async and must be awaited inside a Tokio runtime.

External consumers embed this crate alongside `stellar-agent-network` to sign and submit transactions without spawning the CLI subprocess; see `examples/embed/` in the repository for a complete walkthrough. Network transport, transaction assembly, and signing live in `stellar-agent-network`.

It is part of the stellar-agent-wallet workspace and backs the `stellar-agent-cli` and `stellar-agent-mcp` binaries.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
