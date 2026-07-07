# stellar-agent-smart-account

Smart-account orchestration layer for the stellar-agent-wallet.

This crate wraps the OpenZeppelin `stellar-accounts` on-chain contract surface into typed off-chain primitives the wallet uses for smart-account deployment, context-rule install and auth-digest binding, WebAuthn passkey signers, atomic signer-threshold updates, WASM-hash pinning, verifier migration, active-rule enumeration, multicall, and a configurable upgrade timelock.

It does not submit transactions or connect to a network (that is `stellar-agent-network`), does not evaluate wallet policy rules (that is `stellar-agent-core`), and does not manage keypairs or the platform keyring.

It is part of the stellar-agent-wallet workspace and backs the smart-account flows driven by the `stellar-agent-cli` and `stellar-agent-mcp` binaries rather than being used directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
