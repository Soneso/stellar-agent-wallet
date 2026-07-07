# stellar-agent-stablecoin

Stablecoin substrate for the stellar-agent-wallet.

This crate provides issuer-account pins (USDC and EURC per network), a denomination-explicit resolver that maps a SEP-41 C-address, a code plus issuer, or a bare code through the pin table, a hard-refusal rule for USDT, clawback-flag disclosure types, and a typed trustline preview surface. It registers no MCP tool and no CLI subcommand, performs no on-chain submission, and covers classic G-account trustlines only, with no Soroban or smart-account paths.

It is part of the stellar-agent-wallet workspace. Most users reach this logic through the `trustline` verb in the `stellar-agent-cli` and `stellar-agent-mcp` binaries rather than directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
