# stellar-agent-test-support

Internal test-support crate for the stellar-agent-wallet.

This crate provides the workspace's test harness: log capture and secret-leakage assertions (checking that no S-strkeys, BIP-39 mnemonic words, or sensitive field values reach a `tracing` layer), an in-memory keyring mock so no OS keychain dialog appears during unit tests, Stellar XDR and strkey fixtures, HTTP and contract test doubles, live-network helpers for testnet-acceptance tests (behind the `testnet-helpers` feature), and an RAII guard for overriding the wallet home directory. Optional functionality is gated behind the `test-helpers`, `testnet-helpers`, `verifier-registry`, and `wiremock-helpers` features.

The other workspace crates consume it as a dev-dependency or behind their own test-only feature flags; it never appears in a default production build. It is not designed for standalone use.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
