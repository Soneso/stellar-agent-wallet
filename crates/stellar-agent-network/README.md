# stellar-agent-network

See [Mainnet configurations and scope](../../docs/getting-started.md#mainnet-configurations-and-scope)
for build configuration, admitted operations, and exclusions.

Stellar RPC network client, account query, transaction assembly, and hardware-signing adapter for the stellar-agent-wallet.

This crate provides a typed wrapper around `stellar-rpc-client`, the account-view projection (`AccountView`, `fetch_account`), transaction assembly (`ClassicOpBuilder`, `builder::Asset`), SEP-29 memo-required enforcement, hardware-signer preparation (`SigningKey`), Friendbot funding, the submission primitive (`submit_transaction_and_wait`), and an idempotent submit wrapper. External embedders pair this crate with `stellar-agent-core` to sign and submit transactions without spawning the CLI.

Policy evaluation lives in `stellar-agent-core`. This crate resolves sealed
authorization and independently checks it at signing and submission. All account
and submission traffic goes through Stellar RPC.

The wallet's own signing paths sign mainnet payloads only under mainnet
authorization. The signing primitives this crate exports enforce it too: every
`Signer`, `KeyringSignHandle` included, takes a typed payload from
`signing::payload`, and a mainnet transaction or Soroban authorization payload
exists only under a mainnet authorization. Code running as the same OS user
with access to a keyring entry can read its seed directly. The keyring entry
is the custody boundary. Ordinary submission refuses the declared mainnet
passphrase or known mainnet host before RPC. The authorized entry points
accept only a sealed authorization, which a build without `mainnet-write`
cannot produce.

It is part of the stellar-agent-wallet workspace and backs the `stellar-agent-cli` and `stellar-agent-mcp` binaries.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
