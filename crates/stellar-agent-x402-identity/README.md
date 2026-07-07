# stellar-agent-x402-identity

SEP-10 counterparty-identity pre-payment gate for x402 Exact Stellar payments (payer side) in the stellar-agent-wallet.

x402 has no native identity wire field, so this crate binds the counterparty's identity as an HTTP-layer companion. Before constructing a `PAYMENT-SIGNATURE` payload, the wallet resolves the server's identity via SEP-10 Stellar Web Authentication and obtains a verified JWT Bearer token that accompanies the payment. The Soroban transaction XDR, SAC auth entry, and payment memo are never mutated to carry the JWT, and the ephemeral SEP-10 key is unfunded and is not the payment's funding-account signer.

The crate is payer-side only: SEP-45, payee or facilitator logic, session reuse, and on-chain submission are out of scope. It produces the JWT; the payment payload itself is produced by `stellar-agent-x402`.

It is part of the stellar-agent-wallet workspace. Most users interact with it through the `stellar_x402_authenticated_payment` tool in `stellar-agent-mcp` rather than directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
