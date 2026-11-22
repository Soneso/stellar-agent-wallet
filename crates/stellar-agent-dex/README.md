# stellar-agent-dex

Soroswap DEX swap adapter for the stellar-agent-wallet.

This crate implements the `stellar-agent-defi` `DefiAdapter` trait for the Soroswap router-direct swap path, performing a real on-chain swap. Slippage protection is explicit: an absolute `amount_out_min` is required and a free-form percent string is a structural pre-sign refusal. Immediately before signing, the adapter re-fetches the on-chain quote and refuses if it is absent or below the floor. Token inputs are canonicalized per SEP-41/SAC, ambiguous inputs are refused, the swap deadline is bounded, and the swap path is explicit and never auto-routed. The router address and WASM hash are pinned per network and verified first. The pubnet WASM hash pin is unset, so a pubnet swap refuses with `DexPinError::PinNotSet`.

Soroswap is the only wired venue; a route through an un-allowlisted venue is refused. The Soroswap aggregator (multi-venue distribution) path is not included.

It is part of the stellar-agent-wallet workspace. Most users interact with it through the `stellar-agent-cli` `trade` verb and the `stellar-agent-mcp` tools `stellar_dex_trade` (signing) and `stellar_dex_quote` (read-only) rather than directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
