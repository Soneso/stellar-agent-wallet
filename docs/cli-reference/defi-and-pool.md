# CLI reference: DeFi and the channel pool

This page documents the `stellar-agent` commands for DeFi venues — `lend` (Blend), `vault` (DeFindex), `trade` (Soroswap) — and the channel-account pool subcommands `pool init`, `pool list`, and `pool status`.

The binary is `stellar-agent`. Under the `stellar-cli` external-binary plugin convention it is also reachable as `stellar agent ...`. See [the CLI reference index](index.md) for installation, the JSON envelope shape, and the global flags referenced below.

Every command emits a JSON envelope on stdout by default and returns exit code `0` on success, `1` on any error.

## Shared behavior across the DeFi commands

`lend`, `vault deposit`, `vault withdraw`, and `trade` are all signing commands. Each one, before it signs anything:

1. Loads the named profile (`--profile`, default `default`) and resolves the CAIP-2 chain id, RPC endpoint, and network passphrase from it.
2. Pins the target contract by WASM hash (a two-RPC cross-check when `--secondary-rpc-url` is supplied) so the address you name actually runs the code the wallet expects.
3. Evaluates the operator policy engine for the corresponding tool descriptor. A `Deny` decision refuses with `policy.deny.<code>`. A `RequireApproval` decision refuses with `policy.approval_required` and a message directing you to the MCP server for two-phase approval — the CLI has no interactive approval path for these verbs. A policy engine that is configured but cannot be built refuses with `policy.engine_unavailable` (fail-closed: the value-moving operation does not run permissively).
4. Loads the signing key from the OS keyring entry named by the profile, then signs and submits through the venue adapter.

These commands do not accept `--output`; they always emit JSON. Only the `pool` subcommands offer `--output`.

### Network constraint

The default network is testnet (`stellar:testnet`). These DeFi commands and the `pool` commands carry no command-level mainnet refusal — they are constrained instead by per-network contract pins (Blend and Soroswap resolve different pinned addresses or WASM sets per network; the DeFindex vault WASM hash is identical on testnet and mainnet). `trade` rejects a network it has no pinned router for with `dex.unrecognised_network`. Friendbot funding remains testnet-only. For the contract-pinning and venue model, see [Protocols and venues](../protocols.md).

## `stellar-agent lend`

Supply, withdraw, borrow, or repay against a Blend lending pool through the wallet smart-account. Venue: Blend.

Before submitting, `lend` runs an ordered trust gate: (1) verify the pool WASM hash against the per-network Blend pool WASM set; (2) read the pool's oracle address and require it to be in the Reflector allowlist (else `blend.oracle_not_allowlisted`); (3) check oracle price staleness against the threshold (else `oracle.staleness_exceeded`). Only then does the operator-policy evaluation and submit proceed. Passing `--override-oracle-staleness` bypasses the staleness block and unconditionally emits an `oracle.staleness_overridden` audit event, parallel to the vault upgradable override.

Only the six supply/borrow/repay/withdraw operations below are accepted by `--op`. Blend liquidation operations are not exposed by this command.

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--profile <NAME>` | Profile to load | Optional | `default` |
| `--pool <C-strkey>` | Blend pool contract address | Required | — |
| `--from <C-strkey>` | Wallet smart-account address submitting the request | Required | — |
| `--op <OP>` | Operation: `supply`, `withdraw`, `supply-collateral`, `withdraw-collateral`, `borrow`, `repay` | Required | — |
| `--asset <C-strkey>` | Asset contract address for the operation | Required | — |
| `--amount <i128>` | Amount in the asset's base unit (integer, no decimals) | Required | — |
| `--override-oracle-staleness` | Bypass the oracle staleness block | Optional | `false` |
| `--secondary-rpc-url <URL>` | Second RPC endpoint for the two-RPC pool WASM-hash cross-check | Optional | none |
| `--max-staleness-secs <SECS>` | Maximum accepted oracle staleness; `0` forces a staleness block | Optional | `600` |

Example:

```bash
stellar-agent lend \
  --pool CABC...WXYZ \
  --from CABC...WXYZ \
  --op supply \
  --asset CABC...WXYZ \
  --amount 500000000 \
  --profile default
```

## `stellar-agent vault deposit`

Deposit assets into a DeFindex vault through the wallet smart-account. Venue: DeFindex.

The ordered trust gate is: (1) verify the vault WASM hash; (2) read the upgradable flag; (3) read the four vault role addresses and compute self-managed vs delegated management mode; (4) read the on-chain assets, validate the `--amounts-min` length against the pinned asset count (else `vault.asset_count_mismatch`), and detect Blend-backed strategies; (5) evaluate the upgradable flag in light of the management mode. By default a vault whose upgradable flag is `true` is refused with `vault.upgradable_refused`. Pass `--override-upgradable` to proceed; doing so emits a `vault.upgradable_override` audit event.

A self-managed vault — one where the depositor holds every fund-affecting role (Manager, with no separate third-party emergency or rebalance manager) — is exempt from the upgradable refusal. The refusal guards against a third-party manager swapping the vault implementation under the depositor; when the depositor holds those roles, an upgrade requires their own key, so the guard does not apply. For a self-managed vault the refusal never fires and `--override-upgradable` is ignored. All other management modes are subject to the refusal and its override and audit path.

`--amounts-min` is required. Omitting it is a structural pre-sign refusal — there is no implicit "no minimum". A value of `0` per asset means no slippage protection on that asset, which you opt into explicitly.

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--profile <NAME>` | Profile to load | Optional | `default` |
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
| `--profile <NAME>` | Profile to load | Optional | `default` |
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
| `--profile <NAME>` | Profile to load | Optional | `default` |
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

Fund `N` channel accounts on-chain via a single CAP-33 sponsored-reserve sandwich transaction. Signing command: the funder signer is loaded from the keyring, and the profile's audit chain key must be minted (`profile rotate-audit-key`) — the audit writer is acquired before any seed generation or submit, refusing `audit.chain_key_unavailable` otherwise, and is reused for the post-confirm `channel_pool_initialised` row. The pool master seed is generated in memory and written to the OS keyring only after the on-chain transaction confirms; the public `PoolConfig` bookkeeping is then persisted to the profile TOML. A failure before confirmation leaves no keyring entry and no config, so a clean retry needs no `--force`.

The persistence step patches only the two pool keys (`pool_master_key_id`, `[pool_config]`) on the on-disk profile document; every other stored key is preserved verbatim. `STELLAR_AGENT_*` environment overrides remain load-time-only: an override present during `pool init` affects that run (for example which RPC endpoint it submits to) but is never written into the profile.

`--size` must be in the range `1..=19`. The bound exists because the funder plus each channel must sign the sandwich envelope, and `N+1` signatures must fit the 20-signature cap. A size outside this range is rejected before any network call. Pool refusals surface on the envelope as `error.code` `internal.unexpected_state`; the `error.message` carries the fixed prefix `unexpected internal state:` followed by the specific pool reason (such as `pool.size_out_of_range:` or `pool.already_initialised:`), rather than a distinct top-level code.

If a pool master key already exists for the profile, `pool init` refuses (message `pool.already_initialised:`) unless `--force` is given. The existence probe fails closed: an ambiguous keyring backend error (as opposed to a definite "absent") also refuses, even without `--force`, rather than risk overwriting a key that may exist but is temporarily unreadable. Using `--force` to overwrite the master orphans all previously funded channels.

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--size <N>` | Number of channel accounts to create (`1..=19`) | Required | — |
| `--profile <NAME>` | Profile for the funder key and RPC endpoint | Optional | `default` |
| `--force` | Overwrite an existing pool master key (orphans previously funded channels) | Optional | `false` |
| `--output <FORMAT>` | Output format: `json` or `table` | Optional | `json` |

Example:

```bash
stellar-agent pool init --size 5 --profile default
```

The success result reports the channel count, the channel records (BIP-44 index plus public G-strkey), a redacted transaction hash, the confirmation ledger, a redacted funder address, and the keyring service and account where the master seed is stored. No seed bytes appear in the output.

### `stellar-agent pool list`

List every pool channel with its BIP-44 index, public G-strkey, and live on-chain sequence number (fetched per channel). Read-only. Requires an initialised pool; otherwise it refuses with `error.code` `internal.unexpected_state` and the message `pool.not_initialised:`. A channel whose sequence fetch fails omits the `sequence_number` field for that channel (no value emitted) rather than failing the whole command.

The output includes a note; see the `in_flight` caveat under `pool status` below.

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--profile <NAME>` | Profile to load | Optional | `default` |
| `--output <FORMAT>` | Output format: `json` or `table` | Optional | `json` |

Example:

```bash
stellar-agent pool list --profile default
```

### `stellar-agent pool status`

Report pool utilisation: `initialised`, `pool_size`, `free`, and `in_flight`. Read-only and makes no network call — it reads the persisted `PoolConfig` only. In a fresh CLI invocation `free == pool_size` and `in_flight == 0`. The result carries a note that `free` and `in_flight` reflect the persisted config of a stateless process, not a live allocator; do not read `in_flight: 0` as "safe to flood".

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--profile <NAME>` | Profile to load | Optional | `default` |
| `--output <FORMAT>` | Output format: `json` or `table` | Optional | `json` |

Example:

```bash
stellar-agent pool status --profile default
```

## Related pages

- [CLI reference index](index.md) — installation, the JSON envelope, and global flags.
- [Protocols and venues](../protocols.md) — the contract-pinning model and supported DeFi venues.
