# stellar-agent-smart-account

Smart-account orchestration layer for the stellar-agent-wallet.

This crate wraps the OpenZeppelin `stellar-accounts` on-chain contract surface into typed off-chain primitives. The wallet uses them for smart-account deployment, context-rule install and auth-digest binding, WebAuthn passkey signers, atomic signer-threshold updates, WASM-hash pinning, verifier migration, active-rule enumeration, multicall, and a configurable upgrade timelock.

It reads chain state and submits transactions through the RPC client and submit path of `stellar-agent-network`. The policy engine is in `stellar-agent-core`; this crate calls it only to gate multicall bundles. The crate does not manage keypairs or the platform keyring.

It is part of the stellar-agent-wallet workspace and backs the smart-account flows of the `stellar-agent` executable, which runs both the CLI and the MCP server. It is not used directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
