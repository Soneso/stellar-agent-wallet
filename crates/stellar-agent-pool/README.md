# stellar-agent-pool

Channel-account pool for the stellar-agent-wallet.

This crate manages a set of pre-funded Stellar channel accounts whose sequence numbers are tracked in-pool, so N concurrent tasks can submit transactions without `tx_bad_seq` errors from pool contention. Channels are SEP-5-derived from a pool master seed held in the OS keyring. `pool init --size N` funds N channels on-chain via a single CAP-33 sponsored-reserve transaction; `acquire()` allocates a free channel or returns `resource.pool_exhausted`; `release()` returns a channel and advances or re-fetches its sequence based on outcome; `submit_pooled(...)` acquires, signs, submits, and releases in one call.

It does not submit transactions itself (that is `stellar-agent-network`), does not generate mnemonics (that is `stellar-agent-derive`), and does not hold channel secrets persistently; secrets are re-derived on demand from the OS keyring.

It is part of the stellar-agent-wallet workspace. Most users interact with it through the `stellar-agent-cli` `pool init` / `pool list` / `pool status` subcommands rather than directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
