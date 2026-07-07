# stellar-agent-nonce

HMAC-SHA256 wallet-issued nonce with a replay window and key rotation for the stellar-agent-wallet.

This crate provides `Nonce` (a 48-byte opaque value transmitted as base64), `NonceMint` (a per-profile minter that holds no key bytes and lazy-loads the HMAC key from the platform keyring on each call, zeroising it immediately after), `ReplayWindow` (an in-memory single-use nonce tracker with TTL eviction, fail-closed on process restart), a runtime-free `ToolCatalogue` trait, and `rotate_nonce_key` for atomic keyring rotation.

It does not implement MCP tool dispatch, does not persist the replay window across process restarts (by design), and does not generate XDR envelopes.

It is part of the stellar-agent-wallet workspace. `stellar-agent-mcp` mints a nonce at simulation time and verifies it at commit time; `stellar-agent-cli` exposes the `profile rotate-nonce-key` subcommand.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
