# CLI reference: DeFi and the channel pool

This page documents the `stellar-agent` commands for DeFi venues — `vault` (DeFindex), `trade` (Soroswap) — and the channel-account pool subcommands `pool init`, `pool list`, and `pool status`.

The binary is `stellar-agent`. Under the `stellar-cli` external-binary plugin convention it is also reachable as `stellar agent ...`. See [the CLI reference index](index.md) for installation, the JSON envelope shape, and the global flags referenced below.

Every command emits a JSON envelope on stdout by default and returns exit code `0` on success, `1` on any error.

## Shared behavior across the DeFi commands

`lend`, `vault deposit`, `vault withdraw`, and `trade` are all signing commands. Each one, before it signs anything:

1. Loads the named profile (`--profile`, else `STELLAR_AGENT_PROFILE`, else `default`) and resolves the CAIP-2 chain id, RPC endpoint, and network passphrase from it.
2. Pins the target contract by WASM hash (a two-RPC cross-check when `--secondary-rpc-url` is supplied) so the address you name actually runs the code the wallet expects.
3. Evaluates the operator policy engine for the corresponding tool descriptor. A `Deny` decision refuses with `policy.deny.<code>`. A `RequireApproval` decision refuses with `policy.approval_required` and a message directing you to the MCP server for two-phase approval — the CLI has no interactive approval path for these verbs. A policy engine that is configured but cannot be built refuses with `policy.engine_unavailable` (fail-closed: the value-moving operation does not run permissively).
4. Loads the signing key from the OS keyring entry named by the profile, then signs and submits through the venue adapter.

These commands do not accept `--output`; they always emit JSON. Only the `pool` subcommands offer `--output`.

### Network constraint

The default network is testnet (`stellar:testnet`). These DeFi commands and the `pool` commands carry no command-level mainnet refusal — they are constrained instead by per-network contract pins (Soroswap resolves a different pinned router per network; the DeFindex vault WASM hash is identical on testnet and mainnet). `trade` rejects a network it has no pinned router for with `dex.unrecognised_network`. Friendbot funding remains testnet-only. For the contract-pinning and venue model, see [Protocols and venues](../protocols.md).

## `stellar-agent vault deposit`

Deposit assets into a DeFindex vault through the wallet smart-account. Venue: DeFindex.

The ordered trust gate is: (1) verify the vault WASM hash; (2) read the upgradable flag; (3) read the four vault role addresses and compute self-managed vs delegated management mode; (4) read the on-chain assets, validate the `--amounts-min` length against the pinned asset count (else `vault.asset_count_mismatch`), and detect Blend-backed strategies; (5) evaluate the upgradable flag in light of the management mode. By default a vault whose upgradable flag is `true` is refused with `vault.upgradable_refused`. Pass `--override-upgradable` to proceed; doing so emits a `vault.upgradable_override` audit event.

A self-managed vault — one where the depositor holds every fund-affecting role (Manager, with no separate third-party emergency or rebalance manager) — is exempt from the upgradable refusal. The refusal guards against a third-party manager swapping the vault implementation under the depositor; when the depositor holds those roles, an upgrade requires their own key, so the guard does not apply. For a self-managed vault the refusal never fires and `--override-upgradable` is ignored. All other management modes are subject to the refusal and its override and audit path.

`--amounts-min` is required. Omitting it is a structural pre-sign refusal — there is no implicit "no minimum". A value of `0` per asset means no slippage protection on that asset, which you opt into explicitly.

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--profile <NAME>` | Profile to load | Optional | `STELLAR_AGENT_PROFILE`, else `default` |
| `--vault <C-strkey>` | DeFindex vault contract address | Required | — |
| `--from <C-strkey>` | Wallet smart-account address submitting the deposit | Required | — |
| `--amounts-desired <i128>...` | Desired deposit amount per asset, in declaration order (one or more values) | Required | — |
| `--amounts-min <i128>...` | Minimum accepted amount per asset (same length as `--amounts-desired`); `0` disables slippage protection on that asset | Required | — |
| `--invest` | Auto-invest immediately after deposit | Optional | `false` |
| `--override-upgradable` | Proceed on an `upgradable:true` vault; emits a `vault.upgradable_override` audit event | Optional | `false` |
| `--secondary-rpc-url <URL>` | Second RPC endpoint for the two-RPC WASM-hash cross-check | Optional | none |

Example:

```bash
stellar-agent vault deposit \
  --vault CABC...WXYZ \
  --from CABC...WXYZ \
  --amounts-desired 1000000000 \
  --amounts-min 900000000 \
  --profile default
```

## `stellar-agent vault withdraw`

Withdraw assets from a DeFindex vault by redeeming shares. Same venue, signing posture, and five-step trust gate as `vault deposit`.

`--min-amounts-out` is required. Omitting it is a structural pre-sign refusal.

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--profile <NAME>` | Profile to load | Optional | `STELLAR_AGENT_PROFILE`, else `default` |
| `--vault <C-strkey>` | DeFindex vault contract address | Required | — |
| `--from <C-strkey>` | Wallet smart-account address submitting the withdrawal | Required | — |
| `--shares <i128>` | Number of vault shares to redeem (raw on-chain value) | Required | — |
| `--min-amounts-out <i128>...` | Minimum amount to receive per asset (one or more values) | Required | — |
| `--override-upgradable` | Proceed on an `upgradable:true` vault | Optional | `false` |
| `--secondary-rpc-url <URL>` | Second RPC endpoint for the two-RPC WASM-hash cross-check | Optional | none |

Example:

```bash
stellar-agent vault withdraw \
  --vault CABC...WXYZ \
  --from CABC...WXYZ \
  --shares 5000000 \
  --min-amounts-out 4500000 \
  --profile default
```

## `stellar-agent trade`

Swap tokens via the Soroswap router (`swap_exact_tokens_for_tokens`) through the wallet smart-account. Venue: Soroswap.

The router address and WASM hash are resolved per-network; a network with no pinned router is refused with `dex.unrecognised_network`. The adapter's trust gate runs the venue allowlist check, the two-RPC router WASM-hash pin, and an on-chain `router_get_amounts_out` slippage re-check immediately before signing.

`--amount-out-min` is an absolute minimum-output floor in base units, not a slippage percentage. You supply the concrete floor; the command does not derive one for you.

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--profile <NAME>` | Profile to load | Optional | `STELLAR_AGENT_PROFILE`, else `default` |
| `--from <C-strkey>` | Wallet smart-account address submitting the swap | Required | — |
| `--amount-in <i128>` | Exact input token amount in base units | Required | — |
| `--amount-out-min <i128>` | Minimum output amount, as an absolute floor (not a percent) | Required | — |
| `--path <ASSET>` | One swap-path element; repeat the flag to build the path. First element is the input token, last is the output token. The path is validated to have at least two and at most five elements before signing. Each value is a C-strkey, `native`, or `CODE:ISSUER` | Required | — |
| `--deadline <UNIX_SECS>` | Swap deadline as a Unix timestamp in seconds; refused when more than 3600 seconds (1 hour) in the future | Optional | `now + 300s` |
| `--secondary-rpc-url <URL>` | Second RPC endpoint for the two-RPC router WASM-hash cross-check | Optional | none |

Example:

```bash
stellar-agent trade \
  --from CABC...WXYZ \
  --amount-in 10000000 \
  --amount-out-min 9800000 \
  --path CABC...WXYZ \
  --path CABC...WXYZ \
  --profile default
```

There is no separate `quote` subcommand in this alpha; price discovery happens inside `trade` via the on-chain `router_get_amounts_out` re-check at signing time.

## `stellar-agent pool`

The channel pool is a set of channel accounts derived from a single pool master seed, used to submit transactions concurrently. It is not a DeFi venue. Channel accounts derive deterministically at `m/44'/148'/<index>'`. The pool master seed lives only in the OS keyring; channel private keys are never persisted and are re-derived on demand.

### `stellar-agent pool init`

Create `N` channel accounts through a single CAP-33 sponsored-reserve transaction. The funder sponsors their reserves and pays the fee; each account starts with zero balance, so initialization has no transferred-balance legs or spending-cap entries. A receipt and a pending audit row record the transaction before transmission. Confirmation writes its settled row and the `channel_pool_initialised` event.

The funder signer comes from the keyring. The profile's audit chain key must be minted with `profile rotate-audit-key`; the command acquires the audit writer before generating the pool seed or submitting the transaction. It persists the seed in the keyring and a public `[pool_initialization]` checkpoint in the profile before any send. The profile stores channel identities and submission hashes, never seed bytes. Persistence patches only the pool keys (`pool_master_key_id`, `[pool_initialization]`, `[pool_config]`); other stored values are preserved and environment overrides remain transient.

`pool init --resume` loads the saved seed and verifies that it derives the recorded channels. When all channel accounts exist, it completes config and audit persistence without another send. With a failed receipt and no channel accounts, it retries the same creation with the same keys and a distinct attempt memo. An unknown outcome or a partial account observation remains pending and leaves the checkpoint unchanged. `pool status` names the transaction hash and completion command. A repeated resume of a completed pool returns its channel summary.

A creation past the endpoint's retention settles as an ambiguous receipt, and resume holds there: that is the state where a second envelope could create the channels twice. Releasing it takes the operator's statement that the transaction did not apply, recorded by `tx receipt clear <ENVELOPE_HASH> --acknowledge`; `pool status` names that command in the pending checkpoint's `clear_with` field. Resume then retries with the same channel keys and the next attempt memo. `--force` is not an escape from this state: it replaces the seed.

`--size` must be in `1..=19`; the funder plus the channels must fit the 20-signature cap. Size and existing-pool refusals use `internal.unexpected_state`, with the pool reason in the message. Recovery-checkpoint failures use `submission.record_unavailable`; keyring and network failures retain their typed codes when available.

An existing pool seed requires `--force` for replacement. Replacing a completed pool's seed makes its funded channels unreachable through that seed. While initialization is pending, `--force` refuses: use `--resume` to complete it. An ambiguous keyring existence probe also refuses replacement.

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--size <N>` | Number of channel accounts to create (`1..=19`) | Required for a new initialization | — |
| `--timeout-seconds <N>` | Confirmation deadline for the creation transaction | Optional | `120` |
| `--resume` | Complete pending initialization using the saved seed; excludes `--size` and `--force` | Optional | `false` |
| `--profile <NAME>` | Profile for the funder key and RPC endpoint | Optional | `STELLAR_AGENT_PROFILE`, else `default` |
| `--force` | Replace a completed pool seed; refuses while pending | Optional | `false` |
| `--output <FORMAT>` | Output format: `json` or `table` | Optional | `json` |

Example:

```bash
stellar-agent pool init --size 5 --profile default
```

The success result reports the channel count, the channel records (BIP-44 index plus public G-strkey), a redacted transaction hash when a submission was recorded, the confirmation or account-observation ledger, a redacted funder address, and the keyring service and account where the master seed is stored. No seed bytes appear in the output.

### `stellar-agent pool list`

List every pool channel with its BIP-44 index, public G-strkey, and live on-chain sequence number (fetched per channel). Read-only. Requires an initialised pool; otherwise it refuses with `error.code` `internal.unexpected_state` and the message `pool.not_initialised:`. A channel whose sequence fetch fails omits the `sequence_number` field for that channel (no value emitted) rather than failing the whole command.

The output includes a note; see the `in_flight` caveat under `pool status` below.

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--profile <NAME>` | Profile to load | Optional | `STELLAR_AGENT_PROFILE`, else `default` |
| `--output <FORMAT>` | Output format: `json` or `table` | Optional | `json` |

Example:

```bash
stellar-agent pool list --profile default
```

### `stellar-agent pool status`

Report pool utilisation: `initialised`, `pool_size`, `free`, and `in_flight`. Read-only and makes no network call; it reads the persisted pool config and initialization checkpoint. While initialization is pending, `initialised` is false and `pending` carries the channel count, seed readiness, transaction hash when recorded, and `resume_with` command. A pending checkpoint whose receipt is ambiguous also carries `clear_with`, the acknowledgement command resume requires before it will retry. In a fresh CLI invocation `free == pool_size` and `in_flight == 0`. The result carries a note that `free` and `in_flight` reflect the persisted config of a stateless process, not a live allocator; do not read `in_flight: 0` as "safe to flood".

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--profile <NAME>` | Profile to load | Optional | `STELLAR_AGENT_PROFILE`, else `default` |
| `--output <FORMAT>` | Output format: `json` or `table` | Optional | `json` |

Example:

```bash
stellar-agent pool status --profile default
```

## Related pages

- [CLI reference index](index.md) — installation, the JSON envelope, and global flags.
- [Protocols and venues](../protocols.md) — the contract-pinning model and supported DeFi venues.
