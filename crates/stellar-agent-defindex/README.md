# stellar-agent-defindex

DeFindex vault adapter for the stellar-agent-wallet.

This crate implements the `stellar-agent-defi` `DefiAdapter` trait for the DeFindex vault protocol. It provides typed deposit and withdraw preview and submit with no raw-vector or opaque-calldata signing; `min_out` is required, and its absence is a structural pre-sign refusal. It discloses the four vault roles (Manager, EmergencyManager, RebalanceManager, VaultFeeReceiver), detects self-managed versus delegated vaults, and detects Blend-strategy vaults by WASM hash. An ordered trust gate refuses when a vault is upgradable, with an opt-in override that emits a distinct audit event.

Flash-loan, zapper, and rebalance operations are out of scope.

It is part of the stellar-agent-wallet workspace. Most users interact with it through the `vault` verb dispatched by the `stellar-agent-cli` or `stellar-agent-mcp` binaries rather than directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
