# DeFi and the channel pool

See [Mainnet configurations and scope](https://github.com/Soneso/stellar-agent-wallet/blob/main/docs/getting-started.md#mainnet-configurations-and-scope)
for build configuration, admitted operations, and exclusions.

This reference covers the wallet's DeFi venues (Soroswap
swaps (`trade`) and quotes (`quote`), and DeFindex vaults (`vault`)) and the
SEP-5-derived channel-account pool (`pool`). It lists the CLI commands of the
`stellar-agent` binary and the matching tool names on the `stellar-agent-mcp`
stdio server.

Agents use the MCP trade and vault tools; the signing CLI examples below are
operator workflows. Both surfaces evaluate wallet policy and refuse approval
decisions without creating pending approval. The CLI returns
`policy.approval_required`; the MCP policy gate returns
`policy.approval_required_unsupported`.
Channel-pool initialization is CLI-only operator setup and bypasses wallet
policy. It retains the halt check and mainnet refusal. See
[signing coverage](cli-reference.md#signing-and-approval-coverage).

## Conventions

- CLI binary: `stellar-agent`. Under the `stellar-cli` external-binary plugin
  convention it is also reachable as `stellar agent ...`.
- Result envelope: every CLI command emits a JSON envelope on stdout and
  returns exit code `0` on success, `1` on any error. The envelope shape is
  `{ok, data|error, request_id}`: `ok: true` carries `data`; `ok: false`
  carries `error` (with `code` and `message`).
- Amounts: the CLI DeFi signing flags below take raw integer base units
  (`<i128>`). The MCP DeFi tools take the same raw base units as decimal
  integer strings, e.g. `"10000000"`, never JSON numbers and never with a unit.
- Assets: `native`, `CODE:GISSUER`, or a contract C-strkey. A bare code such as
  `XLM` refuses as ambiguous.
- `chain_id`: every MCP tool listed here requires a `chain_id` argument
  carrying the CAIP-2 chain id (e.g. `stellar:testnet`), which must match the
  loaded profile. `stellar_dex_quote` is the exception: it never matches its
  `chain_id` against the profile and selects the router from it. Its router
  lookup accepts `stellar:testnet` and `stellar:pubnet`. It refuses
  `stellar:mainnet` with JSON-RPC error -32602 and
  `dex.quote.unrecognised_network`.
- Default network: testnet (`stellar:testnet`). Friendbot funding is
  testnet-only.

The MCP tool catalog and envelope details are in `./mcp-tools.md`.

## Shared posture across DeFi commands

`vault deposit`, `vault withdraw`, and `trade` are signing commands.
Before signing, each one:

1. Loads the named profile (`--profile`, else `STELLAR_AGENT_PROFILE`, else
   `default`) and resolves the CAIP-2 chain id, RPC endpoint, and network
   passphrase from it. A halted profile refuses with `profile.halted` after
   this load.
2. Refuses a mainnet profile with `network.mainnet_write_forbidden`, before the
   keyring, the signer, and any RPC call.
3. Pins the target contract by WASM hash (a two-RPC cross-check when
   `--secondary-rpc-url` or the profile's `secondary_rpc_url` supplies a
   secondary) so the named address runs the code the wallet expects. `vault`
   verifies the vault WASM hash before policy evaluation. `trade` verifies the
   router WASM hash inside the adapter, after policy evaluation and the signer
   load.
4. Evaluates the operator policy engine for the tool descriptor. A `Deny`
   refuses with `policy.deny.<code>`. A `RequireApproval` refuses with
   `policy.approval_required`. Neither the CLI nor the MCP server has an
   approval path for these verbs; the MCP tools refuse the same decision with
   `policy.approval_required_unsupported`. A policy
   engine that is configured but cannot be built refuses with its own code,
   such as `policy.engine_selection_unsigned`, or with
   `policy.engine_unavailable`.
5. Acquires the audit writer (`audit.chain_key_unavailable` when the audit key
   is not minted). It then loads the signing key from the OS keyring entry
   named by the profile, and signs and submits through the venue adapter.
   Signing requires a secondary endpoint on the same network and on a host
   other than the primary's; absence refuses with
   `smart_account.ledger_witness_unavailable`. Endpoint disagreement beyond two
   ledgers refuses with `simulation.divergence.ledger_skew`. See
   [Smart-account infrastructure](smart-accounts.md#smart-account-infrastructure)
   for the ledger rules.

These commands do not accept `--output`; they always emit JSON. The `pool`
subcommands accept `--output` (`json` or `table`) and emit JSON for both values.

Shared guardrails: no raw-vector or opaque-calldata signing; a venue/WASM pin is
verified before any signing. Predicted post-op figures are display-only and
never gate signing. `pool init` refuses a mainnet profile as step 2 does. The
DeFindex vault WASM hash is identical on testnet and mainnet; Soroswap resolves
different pinned addresses per network. The MCP DeFi tools refuse a mainnet profile at
entry with `network.mainnet_write_forbidden`, before the policy gate and any RPC
request.

## Command and tool map

| Venue | Verb | CLI | MCP tool | Signs? |
|---|---|---|---|---|
| DeFindex | vault deposit | `stellar-agent vault deposit` | `stellar_defindex_vault_deposit` | signs + submits |
| DeFindex | vault withdraw | `stellar-agent vault withdraw` | `stellar_defindex_vault_withdraw` | signs + submits |
| Soroswap | trade | `stellar-agent trade` | `stellar_dex_trade` | signs + submits |
| Soroswap | quote | (no CLI subcommand) | `stellar_dex_quote` | read-only |

## DeFindex: `stellar-agent vault` / `stellar_defindex_vault_*`

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
5. Evaluate the upgradable flag in light of the management mode. A self-managed
   vault is exempt and ignores `--override-upgradable`: `--from` holds `Manager`,
   and no other address holds `EmergencyManager` or `RebalanceManager`. Any other
   vault with `upgradable:true` refuses with `vault.upgradable_refused`. Pass
   `--override-upgradable` to proceed; the wallet then logs a
   `vault.upgradable_override` warning.

A slippage floor is required. Its absence is a structural pre-sign refusal:
there is no implicit "no minimum". A value of `0` per asset means no slippage
protection on that asset, opted into explicitly.

### `stellar-agent vault deposit`

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--profile <NAME>` | Profile to load | Optional | `STELLAR_AGENT_PROFILE`, else `default` |
| `--vault <C-strkey>` | DeFindex vault contract address | Required | none |
| `--from <C-strkey>` | Wallet smart-account address submitting the deposit | Required | none |
| `--amounts-desired <i128>...` | Desired deposit amount per asset, in declaration order (one or more) | Required | none |
| `--amounts-min <i128>...` | Minimum accepted amount per asset (same length as `--amounts-desired`); `0` disables slippage protection on that asset | Required | none |
| `--invest` | Auto-invest immediately after deposit | Optional | `false` |
| `--override-upgradable` | Proceed on an `upgradable:true` vault that is not self-managed; logs a `vault.upgradable_override` warning | Optional | `false` |
| `--secondary-rpc-url <URL>` | Second RPC endpoint for the two-RPC WASM-hash cross-check and the ledger observation of signing | Required to sign | profile `secondary_rpc_url`, else signing refuses |

```bash
stellar-agent vault deposit \
  --vault CVLT...WXYZ \
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
| `--profile <NAME>` | Profile to load | Optional | `STELLAR_AGENT_PROFILE`, else `default` |
| `--vault <C-strkey>` | DeFindex vault contract address | Required | none |
| `--from <C-strkey>` | Wallet smart-account address submitting the withdrawal | Required | none |
| `--shares <i128>` | Number of vault shares to redeem (raw on-chain value) | Required | none |
| `--min-amounts-out <i128>...` | Minimum amount to receive per asset (one or more) | Required | none |
| `--override-upgradable` | Proceed on an `upgradable:true` vault that is not self-managed | Optional | `false` |
| `--secondary-rpc-url <URL>` | Second RPC endpoint for the two-RPC WASM-hash cross-check and the ledger observation of signing | Required to sign | profile `secondary_rpc_url`, else signing refuses |

```bash
stellar-agent vault withdraw \
  --vault CVLT...WXYZ \
  --from CABC...WXYZ \
  --shares 5000000 \
  --min-amounts-out 4500000 \
  --profile default
```

Refusal codes: `vault.upgradable_refused`, `vault.asset_count_mismatch`, plus the
shared policy codes.

## Soroswap: `stellar-agent trade` / `stellar_dex_trade`

Swap tokens via the Soroswap router (`swap_exact_tokens_for_tokens`) through the
wallet smart-account. The router address and WASM hash are resolved per-network;
a network with no pinned router is refused with `dex.unrecognised_network`.
Soroswap is the only wired venue; routes through an un-allowlisted venue are
refused. The adapter's trust gate runs the venue allowlist check, the two-RPC
router WASM-hash pin, and an on-chain `router_get_amounts_out` slippage re-check
immediately before signing. An absent quote or a quote below the floor refuses
the swap. This re-check is a front-run floor using the swap's own routine, not an
independent oracle.

`--amount-out-min` is an absolute minimum-output floor in base units, not a
slippage percentage. A percent-string slippage is refused, fail-closed. Token
inputs are SEP-41/SAC canonicalized; ambiguous inputs (bare code,
non-canonicalizing code+issuer) are refused before signing. The path is an
explicit address vector and is never auto-routed.

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--profile <NAME>` | Profile to load | Optional | `STELLAR_AGENT_PROFILE`, else `default` |
| `--from <C-strkey>` | Wallet smart-account address submitting the swap | Required | none |
| `--amount-in <i128>` | Exact input token amount in base units | Required | none |
| `--amount-out-min <i128>` | Minimum output amount, as an absolute floor (not a percent) | Required | none |
| `--path <ASSET>` | One swap-path element; repeat the flag to build the path. First element is the input token, last is the output token. The path is validated to have at least two and at most five elements before signing. Each value is a C-strkey, `native`, or `CODE:ISSUER` | Required | none |
| `--deadline <UNIX_SECS>` | Swap deadline as a Unix timestamp in seconds. An omitted deadline defaults to the current time plus 300 seconds; one at or before the current time, or over 3600 seconds ahead, is refused | Optional | `now + 300s` |
| `--secondary-rpc-url <URL>` | Second RPC endpoint for the two-RPC router WASM-hash cross-check and the ledger observation of signing | Required to sign | profile `secondary_rpc_url`, else signing refuses |

```bash
stellar-agent trade \
  --from CABC...WXYZ \
  --amount-in 10000000 \
  --amount-out-min 9800000 \
  --path CTKA...WXYZ \
  --path CTKB...WXYZ \
  --profile default
```

There is no `quote` subcommand on the CLI. CLI price discovery happens inside
`trade` via the on-chain `router_get_amounts_out` re-check at signing time.

Out of scope: the Soroswap aggregator, Aquarius/Phoenix execution, classic SDEX
limit orders (`CreatePassiveSellOffer`), and oracle price-deviation checks.

### Quote: `stellar_dex_quote` (MCP, read-only)

A read-only on-chain Soroswap `router_get_amounts_out` quote for a token path.
Surfaced only as an MCP tool (no CLI subcommand). Requires `chain_id`. Success
returns a bare JSON object with `status: "ok"`, `qty_in`, `expected_out`,
`amounts`, `path_redacted`, and `router_redacted`. A failed quote fetch returns
`dex.quote.fetch_failed` in the standard envelope. It signs nothing and submits
nothing.

## The channel-account pool: `stellar-agent pool`

The channel pool is a set of channel accounts derived from a single pool master
seed, used to submit transactions concurrently. It is not a DeFi venue. Channel
accounts derive deterministically at the SEP-5 path `m/44'/148'/<index>'`. The
pool master seed lives only in the OS keyring; channel private keys are never
persisted and are re-derived on demand. The `pool` subcommands accept
`--output` (`json` or `table`) and emit JSON for both values.

### `stellar-agent pool init`

Create `N` channel accounts in one sponsored-reserve transaction. The funder
signs from the keyring. The seed is persisted before sending, with a public
`[pool_initialization]` checkpoint in the profile. The checkpoint contains
channel identities and submission hashes, never seed bytes.
Use `--resume` to recover it; `--force` cannot replace a pending initialization.

The profile's per-operation fee is capped before a sending path obtains its
unvalued witness. The total fee is that fee times three operations per channel.
On a fresh run, the cap and `validation.fee_total_overflow` checks precede the
funder identity load and any `[pool_initialization]` checkpoint.

The fresh identity load verifies the enrolled funder before RPC. Seed recovery
and receipt settlement on resume precede the fee check. The funder read and
witness precede the signer load that sends, including on retries.
The witness compares the funder and every channel observed absent on the primary.
A disagreement refuses `simulation.divergence`; an unavailable required oracle
refuses `network.witness_unavailable`. Credential refusals retain their own code.

A fresh witness refusal leaves a resumable checkpoint. Every refusal that leaves
a checkpoint carries `error.details.resume_with` with the resume command.
Resume rechecks the fee, funder, and witness.
An over-cap retry consumes no attempt. A witness refusal after retry admission
leaves the incremented attempt persisted, with its prior submission cleared.
The next resume uses that attempt.

A sending result includes `cross_check`, and both submission rows carry a passed
witness. A resume that finishes without signing obtains no witness and checks
no cap. The result has no `cross_check` field.

`--size` must be in `1..=19`. The bound exists because the funder plus each
channel must sign the sandwich envelope, and `N+1` signatures must fit the
20-signature cap. A size outside the range is rejected before any network call.

`pool init` keeps an advisory lock file `profiles/<name>.pool-init.lock`. A
second run while the lock is held refuses with `submission.record_unavailable`.

Size and existing-pool refusals use `internal.unexpected_state`, with the pool
reason (such as `pool.size_out_of_range:` or `pool.already_initialised:`) in
`error.message`. Recovery-checkpoint failures use
`submission.record_unavailable`. Keyring and network failures retain their
typed codes. If a pool master key already exists for the profile, `pool init` refuses
(`pool.already_initialised:`) unless `--force` is given. The existence probe
fails closed: an ambiguous keyring backend error (as opposed to a definite
"absent") also refuses, even without `--force`. Using `--force` to overwrite the
master orphans all previously funded channels.

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--size <N>` | Channels to create (`1..=19`) | Fresh runs | none |
| `--resume` | Recover the saved initialization; excludes `--size` and `--force` | Recovery | `false` |
| `--profile <NAME>` | Profile for the funder key and RPC endpoint | Optional | `STELLAR_AGENT_PROFILE`, else `default` |
| `--force` | Overwrite an existing pool master key (orphans previously funded channels) | Optional | `false` |
| `--timeout-seconds <N>` | Deadline for the endpoint identity check and, separately, for confirming the creation transaction | Optional | `120` |
| `--output <FORMAT>` | `json` or `table`; both emit JSON | Optional | `json` |

```bash
stellar-agent pool init --size 5 --profile default
```

The success result reports the channel count, the channel records (BIP-44 index
plus public G-strkey), a redacted transaction hash when a submission was
recorded, the confirmation or account-observation ledger, a
redacted funder address, and the keyring service and account where the master
seed is stored. No seed bytes appear in the output.

### `stellar-agent pool list`

List every pool channel with its BIP-44 index, public G-strkey, and live
on-chain sequence number (fetched per channel). Read-only. Requires an
initialized pool; otherwise refuses with `error.code` `internal.unexpected_state`
and message `pool.not_initialised:`. A channel whose sequence fetch fails omits
the `sequence_number` field for that channel rather than failing the whole
command. The result carries a `note` with the caveat stated under `pool status`.

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--profile <NAME>` | Profile to load | Optional | `STELLAR_AGENT_PROFILE`, else `default` |
| `--output <FORMAT>` | `json` or `table`; both emit JSON | Optional | `json` |

```bash
stellar-agent pool list --profile default
```

### `stellar-agent pool status`

Report pool utilization: `initialised`, `pool_size`, `free`, and `in_flight`.
Read-only and makes no network call: it reads the pool config, initialization
checkpoint, and the checkpoint's receipt when present. While initialization is
pending, `initialised` is false and `pending` carries `channel_count`,
`seed_ready`, `tx_hash`, and `resume_with`. An ambiguous or failed receipt adds
`clear_with`, the operator acknowledgment command required before resume can
retry; resume retries only once the verified audit history holds its clear row.
In a fresh CLI invocation `free == pool_size` and `in_flight == 0`. The result
carries a note that `free` and `in_flight` reflect the persisted config of a
stateless process, not a live allocator; do not read `in_flight: 0` as "safe to
flood".

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--profile <NAME>` | Profile to load | Optional | `STELLAR_AGENT_PROFILE`, else `default` |
| `--output <FORMAT>` | `json` or `table`; both emit JSON | Optional | `json` |

```bash
stellar-agent pool status --profile default
```

## Refusal code quick reference

| Code | Raised by | Meaning |
|---|---|---|
| `policy.deny.<code>` | all signing verbs | Operator policy denied the operation |
| `policy.approval_required` | CLI signing verbs | Policy requires approval; these verbs have no CLI approval path |
| `policy.approval_required_unsupported` | MCP DeFi signing tools | Policy requires approval; these tools have no approval flow |
| `policy.engine_unavailable` | all signing verbs | Policy engine configured but cannot be built, when the failure has no code of its own |
| `vault.upgradable_refused` | `vault` | Vault `upgradable:true`, not self-managed, and not overridden |
| `vault.asset_count_mismatch` | `vault` | Slippage-vector length differs from pinned asset count |
| `dex.unrecognised_network` | `trade` | No pinned Soroswap router for the network |
| `internal.unexpected_state` (msg `pool.*:`) | `pool` | Pool reason carried in `error.message` |
