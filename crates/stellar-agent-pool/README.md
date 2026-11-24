# stellar-agent-pool

Channel-account pool for the stellar-agent-wallet.

This crate manages a set of pre-funded Stellar channel accounts whose sequence numbers are tracked in-pool, so N concurrent tasks can submit transactions without `tx_bad_seq` errors from pool contention. Channels are SEP-5-derived from a pool master seed held in the OS keyring. `pool init --size N` funds N channels on-chain in one CAP-33 sponsored-reserve transaction. `acquire()` allocates a free channel or returns `resource.pool_exhausted`. `release()` returns a channel and advances or re-fetches its sequence based on outcome. `submit_pooled(...)` acquires, signs, submits, and releases in one call.

It does not submit transactions itself (that is `stellar-agent-network`) and does not generate mnemonics. `stellar-agent-sep5` derives the channel keys from an existing seed. Channel secrets are never held persistently; they are re-derived on demand from the OS keyring.

It is part of the stellar-agent-wallet workspace. Most users interact with it through the `stellar-agent-cli` `pool init` / `pool list` / `pool status` subcommands rather than directly.

The CLI persists the pool seed and a public initialization checkpoint before sending.
An interrupted initialization appears in `pool status`, including its transaction hash
and `pool init --resume` command. Resume derives the same channel keys and completes
configuration for accounts observed on chain. When no channel exists, it retries an
attempt that was never sent. A sent attempt stays pending and is retried only after
`tx receipt clear --acknowledge` records the operator's decision; `pool status`
prints that command for an `ambiguous` or `failed` receipt. Clearing establishes no chain outcome; the
clear reconciles first and writes its clear row before it marks the receipt. `--force` refuses to replace a pending seed.

Library callers supply a nonoptional `SubmissionRecorder` to `InitParams` and
`submit_pooled`. Sponsored initialization has no transferred balance, so its
recorder carries no value legs or spending-cap entries. Callers of `submit_pooled`
supply the value effects of their operation closure to their recorder.
`InitParams::attempt` is a memo ID; increment it for each proven retry so each
attempt retains a distinct receipt.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
