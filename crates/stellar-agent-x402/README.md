# stellar-agent-x402

See [Mainnet configurations and scope](../../docs/getting-started.md#mainnet-configurations-and-scope)
for build configuration, admitted operations, and exclusions.

Rust-native x402 Exact Stellar payment scheme, payer side, for the stellar-agent-wallet.

This crate constructs and signs x402 v2 `PAYMENT-SIGNATURE` payloads for the Exact Stellar scheme via a multi-step validate, identify, build, simulate, cross-check, sign, re-simulate, and finalize flow, wire-compatible with the published `@x402/stellar` package. `exact::create_payment` constructs payments through the ordinary path. `exact::create_payment_authorized` takes bound mainnet proofs and returns the payment with its release authorization. A host integration (for example an MCP tool) delivers the signed payload over HTTP, and the payee or facilitator settles it on-chain.

On the ordinary path, every request of one payment goes to the RPC client the host passes, and the first is an endpoint identity check. When the payment's value requires the cross-check witness, the host also passes a prepared oracle client: the oracle simulates the same unsigned transfer before anything is signed, and the answers are compared. The ordinary path builds no client of its own. The authorized path obtains its primary client from the context and its witness through the bound network helper. It consumes the payment intent before signed re-simulation. The signed authorization first leaves the wallet in the RPC re-simulation, and both paths run a caller-supplied transmit gate immediately before that request. The host can then record the authorization durably or withhold it. `exact::validate_requirements` runs the local checks without a request, so a host can refuse invalid requirements before it admits a payment against a spending window. It refuses a mainnet passphrase or a mainnet-pattern endpoint.

`validate_requirements_for_payment` checks payment fields without keys, storage, or endpoint access. `X402MainnetProofs::with_authenticated` moves the message-use receipt of an authenticated payment into the owned payment proofs. The payment intent is consumed before the signed simulation. The submit authorization is consumed before payload release. On mainnet, the host consumes release authorization and pending approval before returning the payload.

The crate is payer-only: it implements no payee or facilitator logic, targets Stellar Exact (not EVM, not the `upto` scheme, not x402 v3.x), and does not orchestrate the HTTP retry loop. The signed re-simulation exposes the authorization to the configured RPC. The host delivers the payload for settlement.

It is part of the stellar-agent-wallet workspace and is used by the wallet's x402 payment tooling rather than directly by most users.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
