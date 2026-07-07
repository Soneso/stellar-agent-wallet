# stellar-agent-network

Stellar RPC network client, account query, transaction assembly, and hardware-signing adapter for the stellar-agent-wallet.

This crate provides a typed wrapper around `stellar-rpc-client`, the account-view projection (`AccountView`, `fetch_account`), transaction assembly (`ClassicOpBuilder`, `builder::Asset`), SEP-29 memo-required enforcement, hardware-signer preparation (`SigningKey`), Friendbot funding, the submission primitive (`submit_transaction_and_wait`), and an idempotent submit wrapper. External embedders pair this crate with `stellar-agent-core` to sign and submit transactions without spawning the CLI.

It implements no policy evaluation (that lives in `stellar-agent-core`) and does not speak to the Horizon REST API: all account and submission traffic goes through Stellar RPC.

It is part of the stellar-agent-wallet workspace and backs the `stellar-agent-cli` and `stellar-agent-mcp` binaries.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
