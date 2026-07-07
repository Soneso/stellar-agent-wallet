# stellar-agent-blend

Blend Protocol lending adapter for the stellar-agent-wallet.

This crate implements the `stellar-agent-defi` `DefiAdapter` trait for the Blend lending protocol (v1 and v2). It exposes a typed `Vec<BlendRequest>` submit surface with no raw-vector or opaque-calldata signing; unknown request discriminants are refused before signing. Pool WASM hashes are pinned per network and verified before any oracle read or signing.

A simulate-authoritative, fail-closed health check guards lending operations, and a Reflector oracle-staleness policy (600 second default, with a per-invocation override that emits a distinct audit event) gates operations that depend on oracle prices.

It is part of the stellar-agent-wallet workspace. Most users interact with it through the `lend` verb dispatched by the `stellar-agent-cli` or `stellar-agent-mcp` binaries rather than directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
