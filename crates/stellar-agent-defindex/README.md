# stellar-agent-defindex

DeFindex vault adapter for the stellar-agent-wallet.

This crate implements the `stellar-agent-defi` `DefiAdapter` trait for the DeFindex vault protocol. It provides typed deposit and withdraw preview and submit with no raw-vector or opaque-calldata signing; a minimum-output floor is required (`amounts_min` on deposit, `min_amounts_out` on withdraw), and its absence is a structural pre-sign refusal. It discloses the four vault roles (Manager, EmergencyManager, RebalanceManager, VaultFeeReceiver), detects self-managed versus delegated vaults, and detects Blend-strategy vaults by WASM hash. An ordered trust gate refuses an upgradable vault, with an opt-in override that logs a `vault.upgradable_override` warning. A self-managed vault, whose depositor controls every fund-affecting role, is exempt.

Flash-loan, zapper, and rebalance operations are out of scope.

It is part of the stellar-agent-wallet workspace. Most users interact with it through the CLI `vault deposit` and `vault withdraw` commands and the MCP tools `stellar_defindex_vault_deposit` and `stellar_defindex_vault_withdraw` rather than directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
