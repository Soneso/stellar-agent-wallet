# stellar-agent-test-support

Internal test-support crate for the stellar-agent-wallet.

This crate provides the workspace's test harness. Log capture and secret-leakage assertions check that no S-strkeys, BIP-39 mnemonic words, or sensitive field values reach a `tracing` layer. An in-memory keyring mock keeps OS keychain dialogs out of unit tests, and an RAII guard overrides the wallet home directory. The crate also supplies Stellar XDR and strkey fixtures, HTTP and contract test doubles, and live-network helpers for testnet-acceptance tests behind the `testnet-helpers` feature. Optional functionality is gated behind the `test-helpers`, `testnet-helpers`, `verifier-registry`, and `wiremock-helpers` features.

The other workspace crates consume it as a dev-dependency or behind their own test-only feature flags; it never appears in a default production build. It is not designed for standalone use.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
