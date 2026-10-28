# stellar-agent-sep10

See [Mainnet configurations and scope](../../docs/getting-started.md#mainnet-configurations-and-scope)
for build configuration, admitted operations, and exclusions.

SEP-10 Stellar Web Authentication client for the stellar-agent-wallet.

This crate implements the client side of SEP-10 Stellar Web Authentication. `Challenge::parse_and_validate` performs the full challenge validation, fail-closed on every check. `Sep10Session` holds the server-issued JWT and exposes its decoded claims; the JWT signature is not verified because the server-issued token is trusted via TLS. `Sep10Client` provides the async fetch-challenge and submit-signed-challenge HTTP calls, and `auth_with_ephemeral_key` runs the full flow with a fresh per-request ephemeral ed25519 keypair that is zeroized on drop.

`auth_with_ephemeral_key` refuses mainnet before key generation and reports `sep10.mainnet_signing_forbidden`. `sign_challenge_for_test` exists only with the `test-helpers` feature, signs with a caller-supplied key, and refuses mainnet before signing.

`prepare_ephemeral_auth` fetches and validates a challenge without signing it. It generates the ephemeral key and seals the challenge digest and validated network before authorization. In this flow, the challenge must name the ephemeral account before message authorization and again before signing. `complete_ephemeral_auth_authorized` checks the prepared challenge against a message-use receipt before signing. It refuses an unreadable clock and verifies its own signature before submitting the challenge. Mainnet support is limited to bound x402 identity authentication. `sep10.mainnet_authorization_refused` reports that the authorized completion refused before submitting a signed challenge. `complete_ephemeral_auth_authorized` exists only in builds with the `mainnet-write` feature.

It is part of the stellar-agent-wallet workspace. The x402 identity gate consumes this client. Its authorized flow derives the web-auth domain with `web_auth_domain_for_endpoint`.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
