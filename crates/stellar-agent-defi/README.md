# stellar-agent-defi

DeFi adapter substrate for the stellar-agent-wallet.

This crate provides the shared substrate that the protocol adapter crates (DeFindex and Soroswap swaps) build on. It supplies a per-profile, per-network contract-pin framework with a fail-closed sign-time gate, and shared `ScVal` encoding primitives. Its `DefiAdapter` trait and `DefiPreview` type represent no raw-vector or opaque-calldata signing. The submit hand-off of its dispatch-verb seam requires a witness value constructible only from an allow outcome, so a submit path cannot skip the gate.

No live MCP or CLI verb ships in this substrate, and it carries no protocol-specific preview fields, criteria, or guards; those land in the individual protocol crates.

It is part of the stellar-agent-wallet workspace. It is consumed by the protocol adapter crates and, through them, by the CLI and the MCP server of the `stellar-agent` executable rather than used directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
