# stellar-agent-dex

Soroswap DEX swap adapter for the stellar-agent-wallet.

This crate implements the `stellar-agent-defi` `DefiAdapter` trait for the Soroswap router-direct swap path, performing a real on-chain swap. Slippage protection is explicit: an absolute `amount_out_min` is required and a free-form percent string is a structural pre-sign refusal. Immediately before signing, the adapter re-fetches the on-chain quote and refuses if it is absent or below the floor. Token inputs are canonicalised per SEP-41/SAC, ambiguous inputs are refused, the swap deadline is bounded, the swap path is explicit and never auto-routed, and the router address and WASM hash are pinned per network and verified first.

Soroswap is the only wired venue; a route through an un-allowlisted venue is refused. The Soroswap aggregator (multi-venue distribution) path is not included.

It is part of the stellar-agent-wallet workspace. Most users interact with it through the `trade` (signing) and `quote` (read-only) verbs dispatched by the `stellar-agent-cli` or `stellar-agent-mcp` binaries rather than directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
