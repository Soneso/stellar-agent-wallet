# stellar-agent-sep48

SEP-48 contract-interface typed preview and SEP-47 Contract Interface Discovery for the stellar-agent-wallet.

This crate fetches a contract's WASM and parses its SEP-48 spec section to render a typed argument preview of an `InvokeHostFunction` call, and it discovers SEP-47 interface claims from the contract's metadata. The typed preview is non-authoritative display only and does not gate signing; upstream contract specs are treated as trusted and are parsed with bounded XDR limits. The crate submits no transactions and modifies no chain state.

It is part of the stellar-agent-wallet workspace. Most users interact with it through the `stellar_sep48_preview_invocation` and `stellar_sep47_discover` tools in `stellar-agent-mcp` rather than directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
