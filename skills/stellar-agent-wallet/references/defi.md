# DeFi and the channel pool

This reference covers the wallet's DeFi venues — Blend lending (`lend`), Soroswap
swaps (`trade`) and quotes (`quote`), and DeFindex vaults (`vault`) — and the
SEP-5-derived channel-account pool (`pool`). It lists the CLI commands of the
`stellar-agent` binary and the matching tool names on the `stellar-agent-mcp`
stdio server.

## Conventions

- **CLI binary:** `stellar-agent`. Under the `stellar-cli` external-binary plugin
  convention it is also reachable as `stellar agent ...`.
- **Result envelope:** every CLI command emits a JSON envelope on stdout and
  returns exit code `0` on success, `1` on any error. The envelope shape is
  `{ok, data|error, request_id}` — `ok: true` carries `data`; `ok: false`
  carries `error` (with `code` and `message`).
- **Amounts:** at the agent surface, amounts are decimal strings with a unit,
  e.g. `"10 XLM"` or `"500 USDC:GA..."` — never JSON numbers. The CLI DeFi
  signing flags below take raw integer base units (`<i128>`); the agent-facing
  unitful string is parsed to that base unit before signing.
- **Assets:** `native` / `XLM`, or `CODE:GISSUER`, or a contract `C-strkey`.
- **chain_id:** every MCP tool listed here requires a `chain_id` argument
  carrying the CAIP-2 chain id (e.g. `stellar:testnet`), which must match the
  loaded profile.
- **Default network:** testnet (`stellar:testnet`). Friendbot funding is
  testnet-only.

The MCP tool catalog and envelope details are in `./mcp-tools.md`.

## Shared posture across DeFi commands

`lend`, `vault deposit`, `vault withdraw`, and `trade` are signing commands.
Before signing, each one:

1. Loads the named profile (`--profile`, default `default`) and resolves the
   CAIP-2 chain id, RPC endpoint, and network passphrase from it.
2. Pins the target contract by WASM hash (a two-RPC cross-check when
   `--secondary-rpc-url` is supplied) so the named address actually runs the code
   the wallet expects.
3. Evaluates the operator policy engine for the tool descriptor. A `Deny`
   refuses with `policy.deny.<code>`. A `RequireApproval` refuses with
   `policy.approval_required` and directs you to the MCP server for two-phase
   approval — the CLI has no interactive approval path for these verbs. A policy
   engine configured but unbuildable refuses with `policy.engine_unavailable`
   (fail-closed).
4. Loads the signing key from the OS keyring entry named by the profile, then
   signs and submits through the venue adapter.

These commands do not accept `--output`; they always emit JSON. Only the `pool`
subcommands offer `--output`.

Shared guardrails: no raw-vector or opaque-calldata signing; a venue/WASM pin is
verified before any signing; predicted post-op figures are display-only and never
gate signing. `trade` rejects a network with no pinned router via
`dex.unrecognised_network`. The DeFindex vault WASM hash is identical on testnet
and mainnet; Blend and Soroswap resolve different pinned addresses or WASM sets
per network.

## Command and tool map

| Venue | Verb | CLI | MCP tool | Signs? |
|---|---|---|---|---|
| Blend | lend | `stellar-agent lend` | `stellar_blend_lend` | signs + submits |
| DeFindex | vault deposit | `stellar-agent vault deposit` | `stellar_defindex_vault_deposit` | signs + submits |
| DeFindex | vault withdraw | `stellar-agent vault withdraw` | `stellar_defindex_vault_withdraw` | signs + submits |
| Soroswap | trade | `stellar-agent trade` | `stellar_dex_trade` | signs + submits |
| Soroswap | quote | (no CLI subcommand) | `stellar_dex_quote` | read-only |

## Blend — `stellar-agent lend` / `stellar_blend_lend`

Supply, withdraw, borrow, or repay against a Blend lending pool (Blend v1 and v2)
through the wallet smart-account.

Ordered trust gate before policy evaluation and submit:

1. Verify the pool WASM hash against the per-network Blend pool WASM set.
2. Read the pool's oracle address and require it to be in the Reflector
   allowlist, else `blend.oracle_not_allowlisted`.
3. Check oracle price staleness against the threshold, else
   `oracle.staleness_exceeded`.

Only the six operations below are accepted by `--op`. Liquidation, flash-loan,
and `submit_with_allowance` (v2-only) are not exposed. The predicted post-op
health factor is display-only and never gates signing.

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--profile <NAME>` | Profile to load | Optional | `default` |
| `--pool <C-strkey>` | Blend pool contract address | Required | — |
| `--from <C-strkey>` | Wallet smart-account address submitting the request | Required | — |
| `--op <OP>` | One of `supply`, `withdraw`, `supply-collateral`, `withdraw-collateral`, `borrow`, `repay` | Required | — |
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

Refusal codes: `blend.oracle_not_allowlisted`, `oracle.staleness_exceeded`,
plus the shared policy codes.

## DeFindex — `stellar-agent vault` / `stellar_defindex_vault_*`

DeFindex vault deposit and withdraw with four-role disclosure (Manager,
EmergencyManager, RebalanceManager, VaultFeeReceiver), self-managed versus
delegated detection, and Blend-strategy detection by WASM hash. Flash-loan,
zapper, and `rebalance` are out of scope. Per-network WASM pins.

Ordered trust gate (both deposit and withdraw):

1. Verify the vault WASM hash.
2. Read the upgradable flag.
3. Read the four vault role addresses; compute self-managed vs delegated mode.
4. Read on-chain assets, validate the slippage-vector length against the pinned
   asset count (else `vault.asset_count_mismatch`), detect Blend-backed
   strategies.
5. Evaluate the upgradable flag in light of the management mode. A vault with
   `upgradable:true` is refused by default with `vault.upgradable_refused`. Pass
   `--override-upgradable` to proceed; doing so emits a `vault.upgradable_override`
   audit event.

A slippage floor is required. Its absence is a structural pre-sign refusal —
there is no implicit "no minimum". A value of `0` per asset means no slippage
protection on that asset, opted into explicitly.

### `stellar-agent vault deposit`

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--profile <NAME>` | Profile to load | Optional | `default` |
| `--vault <C-strkey>` | DeFindex vault contract address | Required | — |
| `--from <C-strkey>` | Wallet smart-account address submitting the deposit | Required | — |
| `--amounts-desired <i128>...` | Desired deposit amount per asset, in declaration order (one or more) | Required | — |
| `--amounts-min <i128>...` | Minimum accepted amount per asset (same length as `--amounts-desired`); `0` disables slippage protection on that asset | Required | — |
| `--invest` | Auto-invest immediately after deposit | Optional | `false` |
| `--override-upgradable` | Proceed on an `upgradable:true` vault; emits a `vault.upgradable_override` audit event | Optional | `false` |
| `--secondary-rpc-url <URL>` | Second RPC endpoint for the two-RPC WASM-hash cross-check | Optional | none |

```bash
stellar-agent vault deposit \
  --vault CABC...WXYZ \
  --from CABC...WXYZ \
  --amounts-desired 1000000000 \
  --amounts-min 900000000 \
  --profile default
```

### `stellar-agent vault withdraw`

Redeems shares. Same venue, signing posture, and five-step trust gate as
`vault deposit`. `--min-amounts-out` is required; omitting it is a structural
pre-sign refusal.

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--profile <NAME>` | Profile to load | Optional | `default` |
| `--vault <C-strkey>` | DeFindex vault contract address | Required | — |
| `--from <C-strkey>` | Wallet smart-account address submitting the withdrawal | Required | — |
| `--shares <i128>` | Number of vault shares to redeem (raw on-chain value) | Required | — |
| `--min-amounts-out <i128>...` | Minimum amount to receive per asset (one or more) | Required | — |
| `--override-upgradable` | Proceed on an `upgradable:true` vault | Optional | `false` |
| `--secondary-rpc-url <URL>` | Second RPC endpoint for the two-RPC WASM-hash cross-check | Optional | none |

```bash
stellar-agent vault withdraw \
  --vault CABC...WXYZ \
  --from CABC...WXYZ \
  --shares 5000000 \
  --min-amounts-out 4500000 \
  --profile default
```

Refusal codes: `vault.upgradable_refused`, `vault.asset_count_mismatch`, plus the
shared policy codes.

## Soroswap — `stellar-agent trade` / `stellar_dex_trade`

Swap tokens via the Soroswap router (`swap_exact_tokens_for_tokens`) through the
wallet smart-account. The router address and WASM hash are resolved per-network;
a network with no pinned router is refused with `dex.unrecognised_network`.
Soroswap is the only wired venue; routes through an un-allowlisted venue are
refused. The adapter's trust gate runs the venue allowlist check, the two-RPC
router WASM-hash pin, and an on-chain `router_get_amounts_out` slippage re-check
immediately before signing — an absent quote or a quote below the floor refuses
the swap. This re-check is a front-run floor using the swap's own routine, not an
independent oracle.

`--amount-out-min` is an absolute minimum-output floor in base units, not a
slippage percentage. A percent-string slippage is refused, fail-closed. Token
inputs are SEP-41/SAC canonicalised; ambiguous inputs (bare code,
non-canonicalising code+issuer) are refused before signing. The path is an
explicit address vector and is never auto-routed.

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--profile <NAME>` | Profile to load | Optional | `default` |
| `--from <C-strkey>` | Wallet smart-account address submitting the swap | Required | — |
| `--amount-in <i128>` | Exact input token amount in base units | Required | — |
| `--amount-out-min <i128>` | Minimum output amount, as an absolute floor (not a percent) | Required | — |
| `--path <ASSET>` | One swap-path element; repeat the flag to build the path. First element is the input token, last is the output token. Validated to have at least two elements before signing. Each value is a C-strkey, `native`, or `CODE:ISSUER` | Required | — |
| `--deadline <UNIX_SECS>` | Swap deadline as a Unix timestamp in seconds; a missing, zero, or excessively-far deadline is refused | Optional | `now + 300s` |
| `--secondary-rpc-url <URL>` | Second RPC endpoint for the two-RPC router WASM-hash cross-check | Optional | none |

```bash
stellar-agent trade \
  --from CABC...WXYZ \
  --amount-in 10000000 \
  --amount-out-min 9800000 \
  --path CABC...WXYZ \
  --path CABC...WXYZ \
  --profile default
```

There is no `quote` subcommand on the CLI. CLI price discovery happens inside
`trade` via the on-chain `router_get_amounts_out` re-check at signing time.

Out of scope: the Soroswap aggregator, Aquarius/Phoenix execution, classic SDEX
limit orders (`CreatePassiveSellOffer`), and oracle price-deviation checks.

### Quote — `stellar_dex_quote` (MCP, read-only)

A read-only on-chain Soroswap `router_get_amounts_out` quote for a token path.
Surfaced only as an MCP tool (no CLI subcommand). Requires `chain_id`. Returns a
quote envelope; it signs nothing and submits nothing.

## The channel-account pool — `stellar-agent pool`

The channel pool is a set of channel accounts derived from a single pool master
seed, used to submit transactions concurrently. It is not a DeFi venue. Channel
accounts derive deterministically at the SEP-5 path `m/44'/148'/<index>'`. The
pool master seed lives only in the OS keyring; channel private keys are never
persisted and are re-derived on demand. The `pool` subcommands accept
`--output` (`json` or `table`).

### `stellar-agent pool init`

Fund `N` channel accounts on-chain via a single CAP-33 sponsored-reserve sandwich
transaction. Signing command: the funder signer is loaded from the keyring. The
pool master seed is generated in memory and written to the OS keyring only after
the on-chain transaction confirms; the public `PoolConfig` bookkeeping is then
persisted to the profile TOML. A failure before confirmation leaves no keyring
entry and no config, so a clean retry needs no `--force`.

`--size` must be in `1..=19`. The bound exists because the funder plus each
channel must sign the sandwich envelope, and `N+1` signatures must fit the
20-signature cap. A size outside the range is rejected before any network call.

Pool refusals surface on the envelope as `error.code` `internal.unexpected_state`
with the specific pool reason (such as `pool.size_out_of_range:` or
`pool.already_initialised:`) in `error.message`, not as a distinct top-level
code. If a pool master key already exists for the profile, `pool init` refuses
(`pool.already_initialised:`) unless `--force` is given. The existence probe
fails closed: an ambiguous keyring backend error (as opposed to a definite
"absent") also refuses, even without `--force`. Using `--force` to overwrite the
master orphans all previously funded channels.

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--size <N>` | Number of channel accounts to create (`1..=19`) | Required | — |
| `--profile <NAME>` | Profile for the funder key and RPC endpoint | Optional | `default` |
| `--force` | Overwrite an existing pool master key (orphans previously funded channels) | Optional | `false` |
| `--output <FORMAT>` | `json` or `table` | Optional | `json` |

```bash
stellar-agent pool init --size 5 --profile default
```

The success result reports the channel count, the channel records (BIP-44 index
plus public G-strkey), a redacted transaction hash, the confirmation ledger, a
redacted funder address, and the keyring service and account where the master
seed is stored. No seed bytes appear in the output.

### `stellar-agent pool list`

List every pool channel with its BIP-44 index, public G-strkey, and live
on-chain sequence number (fetched per channel). Read-only. Requires an
initialised pool; otherwise refuses with `error.code` `internal.unexpected_state`
and message `pool.not_initialised:`. A channel whose sequence fetch fails omits
the `sequence_number` field for that channel rather than failing the whole
command.

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--profile <NAME>` | Profile to load | Optional | `default` |
| `--output <FORMAT>` | `json` or `table` | Optional | `json` |

```bash
stellar-agent pool list --profile default
```

### `stellar-agent pool status`

Report pool utilisation: `initialised`, `pool_size`, `free`, and `in_flight`.
Read-only and makes no network call — it reads the persisted `PoolConfig` only.
In a fresh CLI invocation `free == pool_size` and `in_flight == 0`. The result
carries a note that `free` and `in_flight` reflect the persisted config of a
stateless process, not a live allocator; do not read `in_flight: 0` as "safe to
flood".

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--profile <NAME>` | Profile to load | Optional | `default` |
| `--output <FORMAT>` | `json` or `table` | Optional | `json` |

```bash
stellar-agent pool status --profile default
```

## Refusal code quick reference

| Code | Raised by | Meaning |
|---|---|---|
| `policy.deny.<code>` | all signing verbs | Operator policy denied the operation |
| `policy.approval_required` | all signing verbs | Needs two-phase approval via the MCP server |
| `policy.engine_unavailable` | all signing verbs | Policy engine configured but unbuildable (fail-closed) |
| `blend.oracle_not_allowlisted` | `lend` | Pool oracle is not in the Reflector allowlist |
| `oracle.staleness_exceeded` | `lend` | Oracle price older than the staleness threshold |
| `vault.upgradable_refused` | `vault` | Vault `upgradable:true`; not overridden |
| `vault.asset_count_mismatch` | `vault` | Slippage-vector length differs from pinned asset count |
| `dex.unrecognised_network` | `trade` | No pinned Soroswap router for the network |
| `internal.unexpected_state` (msg `pool.*:`) | `pool` | Pool reason carried in `error.message` |
