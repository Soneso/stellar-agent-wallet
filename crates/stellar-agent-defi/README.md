# stellar-agent-defi

DeFi adapter substrate for the stellar-agent-wallet.

This crate provides the shared substrate that the protocol adapter crates (Blend, DeFindex, swaps, stablecoins) build on. It supplies a per-profile, per-network contract-pin framework with a fail-closed sign-time gate; the `DefiAdapter` trait and `DefiPreview` type, in which no raw-vector or opaque-calldata signing is representable; a dispatch-verb seam whose submit hand-off requires a witness value constructible only from an allow outcome, so skipping the gate is structurally impossible; and shared `ScVal` encoding primitives.

No live MCP or CLI verb ships in this substrate, and it carries no protocol-specific preview fields, criteria, or guards; those land in the individual protocol crates.

It is part of the stellar-agent-wallet workspace. It is consumed by the protocol adapter crates and, through them, by the `stellar-agent-cli` and `stellar-agent-mcp` binaries rather than used directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
