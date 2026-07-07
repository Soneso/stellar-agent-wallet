# stellar-agent-sep10

SEP-10 Stellar Web Authentication client for the stellar-agent-wallet.

This crate implements the client side of SEP-10 Stellar Web Authentication. `Challenge::parse_and_validate` performs the full challenge validation, fail-closed on every check. `Sep10Session` holds the server-issued JWT and exposes its decoded claims; the JWT signature is not verified because the server-issued token is trusted via TLS. `Sep10Client` provides the async fetch-challenge and submit-signed-challenge HTTP calls, and `auth_with_ephemeral_key` runs the full flow with a fresh per-request ephemeral ed25519 keypair that is zeroized on drop.

It is part of the stellar-agent-wallet workspace and is used by the wallet's SEP-10 authentication and x402 payment paths rather than directly by most users.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
