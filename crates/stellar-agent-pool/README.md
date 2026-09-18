# stellar-agent-pool

Channel-account pool for the stellar-agent-wallet.

This crate manages a set of pre-funded Stellar channel accounts whose sequence numbers are tracked in-pool, so N concurrent tasks can submit transactions without `tx_bad_seq` errors from pool contention. Channels are SEP-5-derived from a pool master seed held in the OS keyring. `pool init --size N` funds N channels on-chain via a single CAP-33 sponsored-reserve transaction; `acquire()` allocates a free channel or returns `resource.pool_exhausted`; `release()` returns a channel and advances or re-fetches its sequence based on outcome; `submit_pooled(...)` acquires, signs, submits, and releases in one call.

It does not submit transactions itself (that is `stellar-agent-network`), does not generate mnemonics (that is `stellar-agent-sep5`), and does not hold channel secrets persistently; secrets are re-derived on demand from the OS keyring.

It is part of the stellar-agent-wallet workspace. Most users interact with it through the `stellar-agent-cli` `pool init` / `pool list` / `pool status` subcommands rather than directly.

The CLI persists the pool seed and a public initialization checkpoint before sending.
An interrupted initialization appears in `pool status`, including its transaction hash
and `pool init --resume` command. Resume derives the same channel keys, completes
configuration for accounts observed on chain, or retries a failed creation when no
channel exists. An unknown outcome remains pending; a creation whose receipt settles
as ambiguous is retried only after `tx receipt clear --acknowledge` records that it
did not apply, which `pool status` names. `--force` refuses to replace a pending seed.

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
