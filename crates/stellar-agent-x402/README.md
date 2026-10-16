# stellar-agent-x402

Rust-native x402 Exact Stellar payment scheme, payer side, for the stellar-agent-wallet.

This crate constructs and signs x402 v2 `PAYMENT-SIGNATURE` payloads for the Exact Stellar scheme via a multi-step validate, identify, build, simulate, sign, re-simulate, and finalize flow, wire-compatible with the published `@x402/stellar` package. The entry point `exact::create_payment` produces the signed payload; a host integration (for example an MCP tool) delivers it over HTTP, and the payee or facilitator settles it on-chain.

Every request of one payment goes to the RPC client the host passes, and the first is an endpoint identity check. The signed authorization first leaves the wallet in the RPC re-simulation, and `create_payment` runs a caller-supplied transmit gate immediately before that request. The host can then record the authorization durably or withhold it. `exact::validate_requirements` runs the local checks without a request, so a host can refuse invalid requirements before it admits a payment against a spending window.

The crate is payer-only: it implements no payee or facilitator logic, targets Stellar Exact (not EVM, not the `upto` scheme, not x402 v3.x), and does not orchestrate the HTTP retry loop.

It is part of the stellar-agent-wallet workspace and is used by the wallet's x402 payment tooling rather than directly by most users.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
