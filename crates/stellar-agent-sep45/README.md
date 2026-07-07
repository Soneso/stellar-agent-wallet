# stellar-agent-sep45

SEP-45 Web Authentication for Contract Accounts, client-side, for the stellar-agent-wallet.

This crate implements the client side of SEP-45 challenge validation and JWT session handling. `AuthorizationEntries::parse_and_validate` enforces the challenge validation steps and is fail-closed. `Sep45Session` holds the server-issued JWT and its decoded claims without verifying the JWT signature, which is spec-compliant since TLS authenticates the server. `Sep45Client` provides the async fetch and submit calls, `auth_with_ephemeral_key` runs the per-request ephemeral-key flow, and `sign_authorization_entries` signs the client entry with one or more persistent signer keypairs and returns re-encoded XDR for submission.

It is part of the stellar-agent-wallet workspace and is used by the wallet's contract-account authentication paths rather than directly by most users.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
