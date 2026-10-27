# stellar-agent-x402-identity

See [Mainnet configurations and scope](../../docs/getting-started.md#mainnet-configurations-and-scope)
for build configuration, admitted operations, and exclusions.

SEP-10 counterparty-identity pre-payment gate for x402 Exact Stellar payments (payer side) in the stellar-agent-wallet.

x402 has no native identity wire field, so this crate binds the counterparty's identity as an HTTP-layer companion. Before constructing a `PAYMENT-SIGNATURE` payload, the wallet resolves the server's identity via SEP-10 Stellar Web Authentication, verifies the challenge, and obtains the JWT Bearer token the server issues over TLS to accompany the payment. The wallet parses the JWT's claims but does not verify its signature. The Soroban transaction XDR, SAC auth entry, and payment memo are never mutated to carry the JWT, and the ephemeral SEP-10 key is unfunded and is not the payment's funding-account signer.

Ordinary identity entries refuse mainnet before any request. `resolve_and_verify_counterparty` and its transport seam, which exists only with the `test-helpers` feature, refuse mainnet before fetching `stellar.toml` and report `identity.mainnet_signing_forbidden`. `resolve_and_verify_counterparty_authorized` binds SEP-10 authentication to the approved payment and home domain. `MainnetIdentityInputs` supplies the authorization inputs. `MainnetCounterpartySession` returns the verified session and message-use receipt for the authorized payment continuation. Its `into_parts` method transfers the session and receipt to the payment caller. `identity.mainnet_authorization_refused` reports that the bound identity authentication refused before submitting a signed challenge. Without `mainnet-write`, the context and receipt inputs needed by the authorized flow cannot be constructed.

The crate is payer-side only: SEP-45, payee or facilitator logic, session reuse, and on-chain submission are out of scope. It produces the JWT; the payment payload itself is produced by `stellar-agent-x402`.

It is part of the stellar-agent-wallet workspace. Most users interact with it through the `stellar_x402_authenticated_payment` tool in `stellar-agent-mcp` rather than directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
