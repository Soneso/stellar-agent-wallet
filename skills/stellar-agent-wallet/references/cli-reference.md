# CLI reference

`stellar-agent` is a self-custodial Stellar wallet for AI agents. It builds, signs, and submits transactions on testnet under a policy engine, an operator-approval spine, and a tamper-evident hash-chained audit log. This file documents the full command surface for an agent driving the CLI. For the MCP tool surface, see `./mcp-tools.md` (ships alongside this file).

## Invocation and global model

The binary is `stellar-agent` on `PATH`. When `stellar` is installed it is also reachable as a plugin: `stellar agent <command> ...`. Examples below use the direct form.

There are no flags on the top-level command. Network, profile, RPC URLs, and signer source are declared per subcommand. Run `stellar-agent --help` for the live subcommand list and `stellar-agent <command> --help` for a group's flags.

### Output envelope and exit codes

Every command prints one JSON object on stdout. Exit code `0` means success; exit code `1` means any error. The standard envelope is:

```json
{"ok": true, "data": { ... }, "request_id": "..."}
{"ok": false, "error": {"code": "...", "message": "..."}, "request_id": "..."}
```

The `credentials` and `toolsets` groups use this same envelope; a `credentials.*` or `toolsets.*` / `toolset.*` wire code identifies the specific refusal.

### Value formats

- Amounts are decimal strings with an explicit unit, e.g. `"10 XLM"`, `"10.5 USDC"`, `"5 XLM"`. Bare numbers and raw stroop strings are rejected on user-facing amount flags. (The DeFi venue flags `lend`/`vault`/`trade` are the exception: they take raw integer base-unit amounts — `i128` / `--amount`, `--shares`, etc. — with no unit.)
- Assets are `native`, `XLM`, or `CODE:ISSUER_GSTRKEY` (e.g. `USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN`). Contract addresses are C-strkeys; classic accounts are G-strkeys; secret keys are S-strkeys.
- `--fee <STROOPS|auto[:pNN]>`: an integer sets explicit stroops; `auto` selects the p95 percentile from `getFeeStats`; `auto:pNN` selects an explicit percentile (`p50`, `p75`, `p95`, `p99`). Absent uses the profile default (100 stroops). Soroban resource fees are added by simulation. (`smart-account multicall` accepts only an integer `--fee`; `auto` is rejected there.)

### Shared flags

These recur with the same meaning across groups:

| Flag | Meaning | Default |
|---|---|---|
| `--profile <NAME>` | Selects the per-environment TOML profile (binds CAIP-2 chain, RPC, keyring entry references, thresholds, policy engine). Holds no secrets. | resolves `--profile` → `STELLAR_AGENT_PROFILE` → `"default"` |
| `--network <NETWORK>` | `testnet` (default) or `mainnet`, case-insensitive | `testnet` |
| `--rpc-url <URL>` | Primary Soroban RPC endpoint (allow-list validated) | `https://soroban-testnet.stellar.org` |
| `--secondary-rpc-url <URL>` | Second RPC for two-RPC cross-checks (WASM-hash divergence) | per command |
| `--timeout-seconds <SECONDS>` | Bounds submission and simulation | `60` |
| `--output <FORMAT>` | `json` (default) or `table`; not accepted on every command | `json` |

### Signer source

Signing commands take a mutually exclusive signer-source group (exactly one):

- The secret-env flag — the **name of an environment variable** holding the source-account S-strkey. Set the variable to your secret; pass the variable name, never the secret. Spelled `--secret-env` on `pay` / `accounts create`, `--deployer-secret-env` on `accounts deploy-c` and the `smart-account deploy-*` verbs (`deploy-webauthn-verifier`, `deploy-ed25519-verifier`, `deploy-spending-limit-policy`), `--signer-secret-env` on the `smart-account` commands.
- `--sign-with-ledger` — sign with a connected Ledger hardware device.
- `--account-index <INDEX>` — BIP-44 account index for the Ledger derivation path. Default `0`.

```bash
export WALLET_SK="S..."   # source-account secret key
stellar-agent pay GDEST...WXYZ "10 XLM" --source GSRC...WXYZ --secret-env WALLET_SK
```

### Mainnet-write refusal

This is a testnet-first alpha. `mainnet` is accepted for read-only commands but every write or signing command structurally refuses `mainnet`: commands that take `--network` refuse before any RPC call and before any signing key is touched, and profile-driven flows are refused at the network submit layer before any transaction is sent. The refusal surfaces as `network.mainnet_write_forbidden` (the `friendbot` command and `accounts create --fund-with-friendbot` use `network.friendbot_mainnet_forbidden`).

---

## accounts

Account-management group. Subcommands: `create`, `deploy-c`.

### `accounts create [NEW_G_STRKEY] [flags]`

Creates a new account in one of two mutually exclusive modes: sponsored `CreateAccount`, or Friendbot funding. Sponsored mode signs with the sponsor key; Friendbot mode signs nothing. `mainnet` parses but is structurally refused (sponsored: `network.mainnet_write_forbidden`; Friendbot: `network.friendbot_mainnet_forbidden`).

Argument groups (parser-enforced): mode (exactly one) `--sponsor` xor `--fund-with-friendbot`; account (exactly one) positional `<NEW_G_STRKEY>` xor `--generate`; signer (sponsored) `--secret-env` xor `--sign-with-ledger`.

| Flag / arg | Meaning | Default |
|---|---|---|
| `<NEW_G_STRKEY>` (positional) | G-strkey of the account to create | — |
| `--generate` | Mint a fresh ed25519 keypair in-process; returns G- and S-strkey in JSON (`data.secret_key`, never in `table`, never logged) | `false` |
| `--sponsor <G_STRKEY>` | Sponsor/source for `CreateAccount` | — |
| `--starting-balance <AMOUNT>` | Starting balance with units, e.g. `"5 XLM"` (sponsored mode) | — |
| `--secret-env <VAR>` | Env-var name holding sponsor S-strkey | — |
| `--sign-with-ledger` / `--account-index <INDEX>` | Ledger signer / BIP index | `false` / `0` |
| `--fund-with-friendbot` | Fund via Friendbot (testnet only) | `false` |
| `--friendbot-url <URL>` | Friendbot endpoint (Friendbot mode) | `https://friendbot.stellar.org` |
| `--network` / `--fee` / `--timeout-seconds` / `--rpc-url` / `--output` | shared (sponsored mode) | as above |

The sponsor public key must match the public key derived from the signer.

```bash
export SPONSOR_SK="S..."
stellar-agent accounts create --generate --sponsor GABC...WXYZ \
  --secret-env SPONSOR_SK --starting-balance "5 XLM"
```

### `accounts deploy-c [flags]`

Deploys a new OpenZeppelin smart-account (C-account) contract via `CreateContractV2`; the genesis signer is installed through the contract `__constructor`. Signs source-account credentials with the deployer key (except `--dry-run`, which derives the C-strkey deterministically with no signing or RPC). `mainnet` parses but is structurally refused for writes.

Argument groups: deployer (exactly one) `--deployer-secret-env` xor `--sign-with-ledger`; salt (at most one) `--salt-hex` xor `--salt-random` (random when neither given); genesis signer source (exactly one) `--initial-signer` xor `--signer-webauthn` xor `--signer-ed25519` xor `--signer-external` (with `--signer-key-data`). `__constructor` takes a single-element signer vec, so exactly one genesis signer is ever installed.

| Flag | Meaning | Default |
|---|---|---|
| `--initial-signer <G_STRKEY>` | Delegated (native) genesis signer | — |
| `--signer-webauthn <CRED_NAME>` | Genesis signer = an already-registered passkey, resolved from the local passkeys registry; needs a WebAuthn verifier already deployed (`deploy-webauthn-verifier`) | — |
| `--signer-ed25519 <HEX_PUBKEY_64>` (optional `--verifier <C_STRKEY>` override) | Genesis signer = raw 32-byte ed25519 pubkey, verified by the Ed25519 verifier resolved from `--verifier` when supplied, else the verifier registry | — |
| `--signer-external <C_STRKEY>` + `--signer-key-data <HEX>` | Genesis signer = verified by this verifier contract with this key data | — |
| `--accept-no-delegated-fallback` | Required with any non-`--initial-signer` genesis source: acknowledges NO G-key fallback exists at genesis (`validation.passkey_only_rule_no_delegated_fallback` otherwise) | `false` |
| `--deployer-secret-env <VAR>` | Env-var name holding deployer S-strkey | — |
| `--sign-with-ledger` / `--account-index <INDEX>` | Ledger deployer / BIP-44 index | `false` / `0` |
| `--salt-hex <HEX64>` | 32-byte salt as 64-char lowercase hex (re-deploy a known C-strkey) | — |
| `--salt-random` | Fresh random 32-byte salt | random default |
| `--profile <NAME>` | Profile whose audit writer receives deploy entries | none |
| `--network` / `--rpc-url` / `--fee` / `--timeout-seconds` / `--output` | shared | as above |
| `--dry-run` | Derive C-strkey only; no signing, no RPC | `false` |

A non-Delegated genesis signer cannot itself authorize any further rule mutation (`smart-account rules`/`signers` authorize only via a Delegated signer); follow up with `smart-account signers add` to attach a Delegated co-signer once a policy is attached to the target rule.

```bash
export DEPLOYER_SK="S..."
stellar-agent accounts deploy-c --initial-signer GABC...WXYZ \
  --deployer-secret-env DEPLOYER_SK --salt-random
```

---

## pay

`pay <DESTINATION> <AMOUNT> [ASSET] [flags]` — sends a classic payment, enforcing SEP-29 memo-required before signing. By default builds, signs, and submits atomically. `mainnet` parses but is structurally refused for writes. `--use-oz-relayer` is not implemented and declines.

Staged pipeline (mutually exclusive): `--build-only` emits unsigned envelope XDR and exits; `--sign-only <XDR>` signs a prebuilt envelope and emits signed XDR; `--submit-only <XDR>` submits a pre-signed envelope.

| Flag / arg | Meaning | Default |
|---|---|---|
| `<DESTINATION>` (positional) | Destination G-strkey | — |
| `<AMOUNT>` (positional) | Amount with units, e.g. `"10 XLM"` | — |
| `[ASSET]` (positional) | `native`, `XLM`, or `CODE:ISSUER` | `native` |
| `--source <G_STRKEY>` | Source account; required for signing | — |
| `--memo-text <STRING>` | Memo text (UTF-8, up to 28 bytes) | — |
| `--memo-id <U64>` | Memo ID (u64 decimal) | — |
| `--memo-hash <64_HEX>` / `--memo-return <64_HEX>` | Memo hash / return hash (32 bytes) | — |
| `--secret-env <VAR>` | Env-var name holding source S-strkey | — |
| `--sign-with-ledger` / `--account-index <INDEX>` | Ledger signer / BIP index | `false` / `0` |
| `--build-only` / `--sign-only <XDR>` / `--submit-only <XDR>` | Stage selection (at most one) | — |
| `--profile <NAME>` | Profile whose policy engine, keys, and audit writer to use | `default` |
| `--fee` / `--network` / `--timeout-seconds` / `--rpc-url` / `--output` | shared | as above |

Memo flags are a mutually exclusive group (at most one).

Under `policy.engine = "v1"` `pay` evaluates operator policy before signing. The staged `--sign-only` / `--submit-only` stages gate too: they decode the supplied envelope and match rules under the `stellar_pay_commit` tool name, and deny `policy.deny.unsizable_value_effect` on an envelope the decoder cannot size unless the matched rule sets `allow_opaque_signing = true`.

```bash
export WALLET_SK="S..."
stellar-agent pay GDEST...WXYZ "10 XLM" --source GSRC...WXYZ \
  --secret-env WALLET_SK --memo-text "invoice-42"
```

---

## mpp

Testnet-only sponsored MPP charge authorization for the profile's classic
G-account signer. The wallet returns a credential; it does not send the paid
request or submit the server-sponsored transaction.

```bash
stellar-agent mpp charge authorize --profile default --input-file challenge.json
stellar-agent mpp charge authorize --profile default --input-stdin < challenge.json
stellar-agent mpp charge authorize --profile default --approval-id <approval-id>
stellar-agent mpp authorization status --profile default --authorization-id <id>
stellar-agent mpp receipt record --profile default --authorization-id <id> \
  --transport http --receipt-file receipt.txt
stellar-agent mpp settlement reconcile --profile default --authorization-id <id> \
  --reference-file transaction-hash.txt
stellar-agent mpp state prune --profile default --reason-file reason.txt
```

Each input operation requires exactly one stdin/file source; files must be
bounded regular non-symlinks. `authorize` returns `mpp.approval_required` when
operator consent is needed. Approve the returned ID through the normal approval
surface, then resume with `--approval-id`; no challenge may be supplied on
resume. Credential output is one-shot and sensitive.

Receipt observation does not prove settlement. Reconcile requires the lowercase
transaction hash and verifies the exact envelope and payer authorization through
RPC. Prune is audited, requires a bounded reason, retains indeterminate records,
and removes only terminal markers older than 30 days.

---

## balances

`balances [flags]` — reads native XLM balance and trustlines via RPC `getLedgerEntries`. Read-only; no mainnet gate. `--account` is required in practice (omitting it exits `1`).

| Flag | Meaning | Default |
|---|---|---|
| `--account <G_STRKEY>` (required) | Account to query | — |
| `--asset <CODE:ISSUER>` | Trustline asset; repeatable (untrusted assets omitted) | none |
| `--rpc-url` / `--output` | shared | as above |

```bash
stellar-agent balances --account GABC...WXYZ \
  --asset USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN
```

---

## trustline

`trustline [flags]` — creates or removes a classic trustline (`ChangeTrust`) behind an ordered trust gate (operator policy, denomination resolution with USDT hard-refusal plus a known-lookalike denylist and pinned-issuer checks, live issuer-flag fetch that fail-closes, clawback gate, typed preview). Builds, signs, submits, waits atomically — no staged pipeline. Network derives from the profile; there is no `--network` flag. USDT cannot be trusted.

| Flag | Meaning | Default |
|---|---|---|
| `--from <G_STRKEY>` (required) | Account that will hold the trustline | — |
| `--asset <ASSET>` (required) | `USDC` (bare, pin table), `CODE:ISSUER`, or a `C...` SAC address (deferred, typed error) | — |
| `--limit-stroops <I64>` | Explicit limit; `0` removes the trustline | unlimited (`i64::MAX`) |
| `--profile <NAME>` | Profile to load | `default` |
| `--chain-id <CAIP2>` | CAIP-2 chain id, e.g. `stellar:testnet` | profile value |
| `--fee` | shared | profile `classic_fee_per_op_stroops` |

```bash
stellar-agent trustline --from GABC...WXYZ --asset USDC --profile default
```

---

## claim

`claim <BALANCE_ID> [flags]` — claims a Stellar `ClaimClaimableBalance` operation for a balance the agent already holds the id of. Enforces the claim guards (claimant membership, predicate satisfaction, non-native trustline state, native-XLM fee affordability) before signing. `mainnet` parses but is structurally refused for writes. Same three-stage pipeline as `pay`: `--build-only` emits unsigned envelope XDR and exits; `--sign-only <XDR>` signs a prebuilt envelope; `--submit-only <XDR>` submits a pre-signed envelope; the default runs all three atomically.

| Flag / arg | Meaning | Default |
|---|---|---|
| `<BALANCE_ID>` (positional) | A `B...` strkey, canonical 72-hex id, or bare 64-hex hash | — |
| `--source <G_STRKEY>` (required) | Claiming account; also the transaction source | — |
| `--fee <STROOPS\|auto[:pNN]>` | Classic fee selector | profile default |
| `--secret-env <VAR>` | Env-var name holding source S-strkey | — |
| `--sign-with-ledger` / `--account-index <INDEX>` | Ledger signer / BIP index | `false` / `0` |
| `--build-only` / `--sign-only <XDR>` / `--submit-only <XDR>` | Stage selection (at most one) | — |
| `--profile <NAME>` | Profile whose policy engine, keys, and audit writer to use | `default` |
| `--network` | `testnet` or `mainnet` (`mainnet` structurally refused for writes) | `testnet` |
| `--timeout-seconds` / `--rpc-url` / `--output` | shared | as above |

Under `policy.engine = "v1"` `claim` evaluates operator policy before signing. The staged `--sign-only` / `--submit-only` stages gate too: they decode the supplied envelope and match rules under the `stellar_claim_commit` tool name, and deny `policy.deny.unsizable_value_effect` on an envelope the decoder cannot size unless the matched rule sets `allow_opaque_signing = true`.

The build stage prints a typed preview (balance id, asset, amount, claimants, `is_claimant`, predicate verdict) to stdout before the guards run, so the operator sees the balance disclosure even when a guard subsequently refuses.

```bash
export WALLET_SK="S..."
stellar-agent claim BAAD...WXYZ --source GSRC...WXYZ --secret-env WALLET_SK
```

---

## friendbot

`friendbot [flags]` — funds a testnet or futurenet account via the Friendbot HTTP endpoint. No local signing. `--network` accepts `testnet`/`futurenet`/`mainnet` at the parser but `mainnet` is refused at dispatch (`network.friendbot_mainnet_forbidden`). The endpoint is allow-list validated (`friendbot.stellar.org`, `friendbot-futurenet.stellar.org`) unless `--friendbot-url-unchecked`.

| Flag | Meaning | Default |
|---|---|---|
| `--account <G_STRKEY>` (required) | Account to fund | — |
| `--network <NETWORK>` | `testnet`/`futurenet`/`mainnet` (mainnet refused) | `testnet` |
| `--friendbot-url <URL>` | Endpoint override; otherwise resolves to the SDF testnet URL regardless of `--network`, so `futurenet` needs an explicit override | `https://friendbot.stellar.org` |
| `--friendbot-url-unchecked` | Bypass URL allow-list (dev/test escape hatch) | `false` |
| `--output` | shared | `json` |

```bash
stellar-agent friendbot --account GABC...WXYZ --network testnet
```

---

## fees

Fee-statistics group. Subcommand: `stats`.

### `fees stats [flags]`

Fetches RPC fee statistics for classic fee selection. Read-only; no mainnet gate. RPC resolves `--rpc-url` → profile `rpc_url` → testnet default.

| Flag | Meaning | Default |
|---|---|---|
| `--profile <NAME>` | Profile whose RPC URL to use | none |
| `--rpc-url <URL>` | Allow-listed RPC override | `https://soroban-testnet.stellar.org` |
| `--output` | shared | `json` |

```bash
stellar-agent fees stats --output table
```

---

## counterparty

Manages the per-profile cache of `stellar.toml` bindings backing the counterparty allowlist policy. None of these sign a transaction; entries are HMAC-protected and skipped on read if verification fails. Subcommands: `list`, `refresh`, `evict`, `warm-up`, `rotate-hmac-key`.

| Subcommand | Form | Notes |
|---|---|---|
| `list` | `counterparty list [--profile NAME] [--json]` | Lists cached bindings (home domain, fetched/expiry timestamps). `--json` is a no-op; JSON is the only shape. Read-only. |
| `refresh` | `counterparty refresh <HOME_DOMAIN> [--profile NAME]` | Force-fetches `https://<domain>/.well-known/stellar.toml`, HMAC-protects, writes atomically. Domain must be strict ASCII, 1–32 chars (IDN/homoglyph rejected). |
| `evict` | `counterparty evict <HOME_DOMAIN> [--profile NAME]` | Deletes one cached binding; exits `0` even if already absent. |
| `warm-up` | `counterparty warm-up [--profile NAME]` | Refreshes every domain in the profile's policy allowlist; exits `1` if any fails. |
| `rotate-hmac-key` | `counterparty rotate-hmac-key [--profile NAME]` | Rotates the per-profile cache HMAC key; existing files then fail verification and need refresh. |

`--profile` defaults to `default` for this group.

```bash
stellar-agent counterparty refresh circle.com --profile default
```

---

## smart-account

Invoke as `stellar-agent smart-account <verb>` or via the shorter `sa` alias. Administration of an on-chain OpenZeppelin smart-account: context rules, signer sets and thresholds, policy contracts, supporting infrastructure (verifier registry, multicall router registry, upgrade timelock), and multicall submission. All write verbs sign through the smart-account auth-entry digest path and take a signer source (exactly one of `--signer-secret-env <VAR>` or `--sign-with-ledger`, plus `--account-index <INDEX>`, default `0`). Most on-chain signing verbs structurally refuse `mainnet`. The `smart-account signers` verbs do not accept `--output`; the other verbs take the shared `--output` (`json` default, `table` where offered).

Every verb's exact flags, the mainnet-refusal matrix, signer-kind discriminators, WASM-hash pinning and override flags, and worked examples live in [`smart-accounts.md`](smart-accounts.md). Per-verb index:

| Verb | Purpose |
|---|---|
| `rules create` | Install a context rule; returns the minted `rule_id`. At least one signer required |
| `rules get` | Read one rule (read-only, mainnet OK) |
| `rules set-name` | Rename a rule |
| `rules set-valid-until` | Change a rule's expiry ledger |
| `rules delete` | Remove a rule |
| `rules verify-pins` | Verify pinned verifier/policy WASM hashes vs on-chain (drift; read-only, exit `1` on drift) |
| `rules add-policy` | Attach a policy (`--kind raw`/`spending-limit`/`simple-threshold`/`weighted-threshold`); cap 5 |
| `rules remove-policy` | Detach a policy by id |
| `rules list` / `list-rules` | Enumerate active rules by on-chain scan (read-only, mainnet OK) |
| `rules get-spending-limit` | Read an installed spending-limit policy's rolling-window budget (read-only; amounts are decimal strings) |
| `rules set-spending-limit` | Retune a spending-limit cap without resetting history. `--auth-rule-id` default 0: the retuned CallContract rule cannot authorize its own retune — name an admin-capable rule. Period is immutable |
| `signers list` | Read the on-chain signer set; baselines if none |
| `signers refresh` | Re-anchor the signer-set baseline |
| `signers add` | Add one signer (cap 15). `--signer-ed25519` is the recommended agent-key shape |
| `signers remove` | Remove a signer; refuses if it would drop below threshold |
| `signers set-threshold` | Change a simple-threshold policy's threshold (authorizer is `--rule-id`) |
| `signers set-weighted-threshold` | Change a weighted-threshold policy's threshold (use an admin `--auth-rule-id` when `--rule-id` is scoped) |
| `signers set-signer-weight` | Change one signer's weight in a weighted-threshold policy |
| `signers batch-add` | Add multiple signers in one transaction (cap 15). Result-fetch needs a simple-threshold policy on the rule |
| `execute` | Submit one `CallContract` invocation authorized by a rule and signed by an External-Ed25519 rule signer — the delegation verb; `--auth-rule-id` has NO default; no MCP equivalent |
| `multicall` | Submit an atomic 1–50-invocation bundle through the registered router; requires `--secondary-rpc-url` (flag or profile, else a typed error) |
| `deploy-webauthn-verifier` | Deploy the OZ WebAuthn-verifier WASM; idempotent; testnet only |
| `deploy-ed25519-verifier` | Deploy the OZ Ed25519-verifier WASM (backs `--signer-ed25519`); testnet only |
| `deploy-spending-limit-policy` | Deploy the OZ spending-limit-policy WASM (per-network singleton); testnet only |
| `deploy-policy` | Deploy any of the three OZ policy contracts via one `--kind`; recommended; testnet only |
| `migrate-verifier` | Move all External signers from one verifier to another across rules; mainnet submit refused, mainnet dry-run allowed |
| `list-verifiers` | Enumerate the compile-time verifier allowlist and audit-status taxonomy (read-only, no network) |
| `register-multicall` / `unregister-multicall` | Edit the local multicall-router registry |
| `timelock schedule` / `cancel` / `execute` / `list-pending` | OpenZeppelin upgrade-timelock lifecycle; write verbs refuse `mainnet`, `list-pending` is read-only |

Flags for every verb: see [`smart-accounts.md`](smart-accounts.md).

---

## DeFi: lend, vault, trade

`lend`, `vault deposit`, `vault withdraw`, and `trade` are signing commands. Before signing each loads the profile, pins the target contract by WASM hash (two-RPC cross-check when `--secondary-rpc-url` is set), evaluates the operator policy engine, then signs and submits. A `Deny` refuses `policy.deny.<code>`; a `RequireApproval` refuses `policy.approval_required` (use the MCP server for two-phase approval — the CLI has no interactive approval path for these verbs); an unbuildable engine refuses `policy.engine_unavailable` (fail-closed). These commands do not accept `--output`; they always emit JSON. There is no command-level mainnet refusal — they are constrained by per-network contract pins. DeFi amounts are raw integer base units (no decimal/unit string).

Every venue's flags, trust gate, refusal codes, and examples live in [`defi.md`](defi.md). Per-verb index:

| Verb | Venue | Purpose |
|---|---|---|
| `lend` | Blend | Supply/borrow/repay/withdraw against a Blend pool; oracle-allowlist and staleness gates |
| `vault deposit` | DeFindex | Deposit into a DeFindex vault; `--amounts-min` required; upgradable-vault refusal |
| `vault withdraw` | DeFindex | Redeem shares from a DeFindex vault; `--min-amounts-out` required |
| `trade` | Soroswap | Swap via the Soroswap router; price discovery is inside `trade` (no separate `quote`) |

Flags for every verb: see [`defi.md`](defi.md).

---

## pool

The channel pool is a set of channel accounts derived from a single pool master seed at `m/44'/148'/<index>'`, used to submit transactions concurrently (not a DeFi venue). The master seed lives only in the OS keyring; channel private keys are re-derived on demand. Subcommands: `init`, `list`, `status`. All accept `--profile` (default `default`) and `--output` (`json` default or `table`).

| Verb | Purpose | Extra flags |
|---|---|---|
| `init` | Fund `N` channels via one CAP-33 sponsored-reserve sandwich; signing. Master seed written to keyring only after confirmation. Refuses if a master exists (message `pool.already_initialised:`, fail-closed on ambiguous probe) unless `--force` (which orphans prior channels). | `--size <N>` (required, `1..=19`); `--force` |
| `list` | List channels (BIP-44 index, public G-strkey, live sequence). Read-only; requires an initialised pool (else `internal.unexpected_state` with `pool.not_initialised:`). | — |
| `status` | Report `initialised`, `pool_size`, `free`, `in_flight`. Read-only, no network (reads persisted `PoolConfig`). `in_flight:0` is not "safe to flood" — it reflects a stateless process. | — |

Pool refusals surface as `error.code` `internal.unexpected_state` with the specific reason (e.g. `pool.size_out_of_range:`, `pool.already_initialised:`) in `error.message`.

```bash
stellar-agent pool init --size 5 --profile default
```

---

## profile

Creates, lists, shows, and migrates profiles, and rotates the keyring-backed keys a profile names. A profile is a per-environment TOML config (schema version 2) holding no secrets. The profile-name argument takes two forms: `init`, `enroll-signer`, `enroll-owner-key`, and `sign-policy` take a `--profile <NAME>` flag (default `default`), while `show`, `migrate`, the `rotate-*` subcommands, and `reset-window-state` take a required positional `<NAME>`. No subcommand has a confirmation flag. All operate on local state — no network, no mainnet gate (`init`'s `--network mainnet` guard is a configuration-time refusal, not the mainnet-write gate). Uses the `{ok, data, request_id}` envelope.

| Verb | Form | Notes |
|---|---|---|
| `init` | `profile init --profile default --network testnet` | State-changing (writes the profile file). Creates a new profile TOML with per-profile-derived keyring refs (placeholder `"default"` signer/nonce accounts) and reports enrollment next steps. Mints no key material, emits no audit row. `--profile <NAME>` (default `default`), `--network <testnet\|mainnet>` (default `testnet`), `--rpc-url <URL>` (optional for testnet; required for mainnet, and must be `https://`), `--engine <v1\|noop>` (default `v1`; v1 needs the key ceremony before the MCP server starts — `next_steps` lists it — while `noop` works immediately once the audit key is minted, via `rotate-audit-key`, required on every engine). Refuses if `<name>.toml` already exists, or if mainnet is selected without an `https://` `--rpc-url`. |
| `list` | `profile list` | Read-only. Returns known profile names sorted as a JSON array. No flags. |
| `show <NAME>` | `profile show default` | Read-only. Resolved config; keyring refs appear as opaque `{service, account}`, secrets never read. Exits `1` with `ProfileNotFound` or an unsupported-version error. |
| `migrate <NAME>` | `profile migrate default` | State-changing (atomic temp+rename). No-op if already current (`status:"no_op"`); else `status:"migrated"` with `from_version`/`to_version`/`path`. |
| `enroll-signer` | `profile enroll-signer --profile default --secret-env WALLET_SK` | State-changing (keyring, and the profile TOML when the account is still a placeholder). Imports the operator's `S...` ed25519 seed from the named env var and stores it verbatim at the profile's `mcp_signer_default` coordinate (the signer every MCP fund-movement tool and keyring-signing CLI verb resolves). Classification uses the raw on-disk value: the literal placeholder `"default"` is pinned to the derived G-strkey (only that key is patched); a pinned G-strkey mismatch refuses; any other value refuses as malformed (`enroll_signer.account_malformed`). `--secret-env <VAR>` (required, the variable name), `--profile <NAME>` (default `default`), `--expected-address <G_STRKEY>`, `--force`. |
| `enroll-owner-key` | `profile enroll-owner-key --profile default --secret-env WALLET_OWNER_SK` | State-changing (keyring). Derives the owner ed25519 PUBLIC key from an operator `S...` seed and stores it at `policy_owner_key_id` (the key the V1 engine verifies against). The seed is never stored. `--expected-address`, `--force`. |
| `sign-policy` | `profile sign-policy --profile default --secret-env WALLET_OWNER_SK` | State-changing (writes the policy file, atomic). Signs `<state_dir>/policies/<profile>.toml` (or `--file`) with the owner seed and writes the `[signature]` table. Refuses if the seed does not match the enrolled owner key. |

### Key-rotation subcommands

Each generates a fresh 32-byte CSPRNG secret, atomically replaces one named keyring entry, and is not reversible. Each takes the profile as positional `<NAME>` and returns `profile` + `rotated`; some add `key_kind`.

The policy-file owner key is NOT rotated here — it is an ed25519 key enrolled with `enroll-owner-key` (public key stored) and used by `sign-policy` (seed supplied at sign time). All rotation subcommands below mint 32-byte HMAC keys.

| Subcommand | Keyring entry | Effect |
|---|---|---|
| `rotate-attestation-key` | approval-spine attestation HMAC (`attestation_key_id`) | Invalidates all pending approvals; the simulate-and-approve round trip must be re-run. `key_kind:"hmac_32_bytes"`. |
| `rotate-audit-key` | audit-log chain-root HMAC (`audit_log_hash_chain_key_id`) | Re-signs every existing per-file chain-root sidecar with the new key, so `audit verify --profile <NAME>` stays green and the old key stops verifying. Adds `key_kind:"hmac_32_bytes"` and `sidecars_resigned`. |
| `rotate-nonce-key` | HMAC nonce key (`mcp_nonce_key_alias`) | Invalidates outstanding nonces. Returns only `profile` + `rotated`. |
| `rotate-counterparty-key` | `stellar.toml` cache-integrity HMAC (`counterparty_cache_key_id`) | Invalidates every cached counterparty binding (re-fetched on next check). Adds `key_kind:"hmac_32_bytes"` and `cache_invalidated:true`. |
| `rotate-policy-state-key` | policy-window-state HMAC (`policy_window_state_key_id`) | Re-signs the persisted window-state store under the new key, so accumulated `per_period_cap` / `rate_limit` history is preserved, not invalidated. Refused if the store does not verify under the current key (use `reset-window-state` instead). Adds `key_kind:"hmac_32_bytes"` and `sidecars_resigned`. |

```bash
stellar-agent profile rotate-attestation-key default
```

Related but not a rotation: `profile reset-window-state <NAME> --reason <REASON>` is the fail-closed recovery path for the persisted policy-window-state store. An unreadable, tampered, or unparseable store makes the stateful criteria (`per_period_cap`, `rate_limit`, and their bundle forms) refuse every matched call until the store is re-initialised; `reset-window-state` re-initialises it to empty (minting the HMAC key if absent), discards all accumulated window history, and writes a `policy_window_state_reset` audit row recording the required `--reason`.

---

## credentials

WebAuthn passkey lifecycle for a profile. The registry holds only public metadata (credential name, redacted credential ID, RP-ID, transports, registration timestamp); the private key never leaves the authenticator. `credential_id` is redacted to first-five-last-five base64url. Uses the standard `{ok, data|error, request_id}` envelope; failures carry a `credentials.*` wire code.

Two common flags: `--profile <NAME>` (resolves `--profile` → `STELLAR_AGENT_PROFILE` → `"default"`), `--rp-id <DOMAIN>` (default `localhost`; set the deployment domain for a self-hosted deployment; IP literals rejected; changing it after registration breaks existing passkeys).

Closed set of `error.code` values across the group: the verb-specific codes in the table below, plus `credentials.invalid_profile_name` (any subcommand, malformed `--profile`), plus these codes shared from the underlying `CredentialsError`: `credentials.not_found`, `.duplicate_name`, `.invalid_name`, `.io_error`, `.registry_parse_failed`, `.registry_serialise_failed`, `.state_dir_unavailable`, `.approval_store_error`, `.approval_store_unavailable`, `.bridge_start_failed`, `.bridge_shutdown_failed`, `.atomic_write_failed`, `.signing_failed`, `.missing_public_key`, `.malformed_public_key`, and a generic `.error` fallback. `add-passkey` additionally emits `.approval_store_dir_unavailable`, `.approval_store_open_failed`, and `.unknown_registration_outcome`. Switch on `error.code`, never on `error.message`.

| Verb | Form | Notes |
|---|---|---|
| `add-passkey <NAME>` | `credentials add-passkey laptop-key --rp-id wallet.example.com` | State-changing; opens the browser to the bridge registration URL and polls. `<NAME>`: 1–64 printable ASCII, no `/ \ :`. Extra flags: `--timeout-seconds` (default `300`), `--accept-rp-id-binding-risk`. First registration prompts `[y/N]` with an RP-ID binding warning unless the flag is set. On success `data` carries the registered credential's metadata; timeout, user cancellation, a missing approval-store entry, or a declined binding warning surface as `ok:false` with `credentials.registration_timeout` / `credentials.registration_user_canceled` / `credentials.registration_entry_missing` / `credentials.rp_id_binding_warning_declined`. |
| `list` | `credentials list` | Read-only. Lists registered passkeys for the profile+RP-ID under `data.credentials`. |
| `show <NAME>` | `credentials show laptop-key` | Read-only. Metadata incl. transports. Exits `1` with `credentials.not_found` when not found. |
| `delete <NAME>` | `credentials delete laptop-key --yes` | State-changing; prompts `[y/N]` (skip with `--yes`/`-y`). Does not remove the on-chain signer. Declining exits `1` with `credentials.delete_canceled`. |

---

## approve

The operator-side half of the approval spine. When a signing-adjacent action needs out-of-band approval, the agent surface records a pending approval and returns an approval nonce; the wallet owner runs `approve --id <NONCE>` in a separate trusted context to inspect a wallet-controlled summary and consent. The summary is rendered from stored fields, not from anything the agent supplied. Approval is bound to the local user (recorded process uid must match at approve time). Uses the `{ok, data, request_id}` envelope.

### `approve --id <NONCE>`

State-changing (records an HMAC attestation, or for a toolset first-invoke gate mints a toolset grant and consumes the entry).

| Flag | Meaning |
|---|---|
| `--id <NONCE>` (required in this form) | Approval nonce from the agent surface's simulate response |
| `--profile <NAME>` | Profile whose attestation key + pending-approval store to use (resolves `--profile` → env → `default`) |
| `--yes` | Non-interactive auto-approve; the summary is still printed |

Interactively prompts `Approve? [y/N]:`; anything other than `y`/`yes` denies. Exits `1` when the nonce is unknown, expired, already attested, created by a different local user, denied, or on I/O error. For payment-style approvals the response returns `approval_attestation` (the HMAC blob the agent must pass as the `approval_attestation` argument to the matching `*_commit` tool); omitted for kinds whose gate reads recorded consent directly (toolset first-invoke grants, trustline clawback opt-ins).

```bash
stellar-agent approve --id ABCxyzNonce
```

```json
{"ok":true,"data":{"approval_nonce":"ABCxyzNonce","attested":true,"process_uid":"501","expires_at_unix_ms":1717000000000,"approval_attestation":"q83vEjRWeJq83v..."},"request_id":"..."}
```

### `approve gc`

State-changing. Evicts every expired entry from the pending-approval store and reports the count (`evicted_count`). When `gc` is present, `--id` is ignored. Evicting zero is a success. `--profile <NAME>` selects the store.

```bash
stellar-agent approve gc --profile default
```

### `approve list`

Read-only. Enumerates pending approvals from the profile's store: opens it, renders a redacted snapshot, and exits. No keyring access, no network calls.

| Flag | Meaning | Default |
|---|---|---|
| `--profile <NAME>` | Profile whose store to read | `default` |
| `--output <FORMAT>` | `json` (default) or `table` | `json` |
| `--include-expired` | Include already-expired entries instead of omitting them | `false` |

`data.expired_count` always reports the number of expired entries regardless of `--include-expired`, so the operator can tell whether `approve gc` is due even when expired entries are hidden.

```bash
stellar-agent approve list --profile default --output table
```

### `approve serve`

Binds a loopback-only HTTP server with a local web UI for the pending-approval queue, so the operator can review and approve/reject entries in a browser instead of running `approve --id <NONCE>` per entry. Runs until Ctrl-C.

| Flag | Meaning | Default |
|---|---|---|
| `--profile <NAME>` | Profile whose store and attestation key to use | `default` |
| `--port <PORT>` | TCP port to bind on `127.0.0.1`; `0` picks an OS-assigned port | `0` |
| `--no-open` | Print the bootstrap URL instead of opening a browser | `false` |
| `--notify <on\|off>` | Best-effort OS toast notification when the queue grows | `on` |
| `--bell` | Emit a terminal bell alongside each queue-growth notice | `false` |
| `--include-expired` | Load the inbox with expired entries shown by default | `false` |

On start the server mints a single-use bootstrap token and prints a `http://127.0.0.1:<port>/bootstrap/<token>` URL; opening it exchanges the token for a session cookie and redirects to the inbox. Must run as the same OS user as the wallet's MCP server process — the attestation binds that user's id.

```bash
stellar-agent approve serve --profile default --port 7823
```

### `approve serve --remote`

Binds a TLS-protected, passkey-authenticated remote-approval surface instead of the loopback inbox, for approving from a device other than the wallet host. Refuses to start unless BOTH the profile has a `[remote_approval]` block with `enabled = true` AND `--confirm-remote-exposure` is also passed — the profile block alone is never sufficient consent. `--port` / `--no-open` / `--notify` / `--bell` / `--include-expired` are ignored in this mode.

| Flag | Meaning |
|---|---|
| `--remote` | Bind the remote surface instead of the loopback inbox |
| `--confirm-remote-exposure` | Required explicit consent, separate from the profile's `enabled` flag |

Every approve or reject on this surface requires a fresh WebAuthn passkey assertion bound to the exact pending entry, in addition to the session login. See `docs/remote-approval.md` in the wallet repository for the full setup guide (the `[remote_approval]` profile block, DNS/hosts-file requirements for `rp_id`, and the login/approve walkthrough).

```bash
stellar-agent approve serve --remote --confirm-remote-exposure --profile default
```

### `approve operator enroll`

Enrolls a WebAuthn passkey credential for the remote-approval surface. Runs entirely locally in both modes below — neither touches the network. Enrollment alone never authorizes the credential; its id must also be added to the profile's `[remote_approval] allowed_credentials` list.

A WebAuthn credential is bound to its `rp.id` at creation time, and a loopback origin can only claim `"localhost"` as an effective domain — that binding decides which mode applies:

- **`--interactive`** — for a loopback or SSH-tunnelled `approve serve --remote` listener. Starts a one-shot local server, prints (and by default opens) an enrollment page, and persists the credential automatically once the ceremony completes. The printed URL carries a single-use bootstrap token exchanged for an HttpOnly session cookie on first visit; serving the page and the credential-persisting POST both require that cookie, and the server binds `127.0.0.1` only. Always produces `rp_id: "localhost"`.
- **`--credential-id` / `--public-key` / `--rp-id` / `--label`** (all four together) — for a domain-configured remote listener. Imports the id and public key from a WebAuthn ceremony run elsewhere, normally the remote listener's own `GET /enroll` page (which has to be served from `https://<rp_id>` for the credential to bind to that domain, and displays a ready-to-run copy of this command).

| Flag | Meaning |
|---|---|
| `--profile <NAME>` | Profile whose operator-credential store to write |
| `--interactive` | Start the loopback ceremony (mutually exclusive with the three credential-import flags `--credential-id`/`--public-key`/`--rp-id`; `--label` still applies, as a page pre-fill) |
| `--no-open` | Print the enrollment URL instead of opening a browser (interactive mode only) |
| `--timeout-seconds <SECS>` | Interactive-ceremony timeout (default: 300) |
| `--credential-id <B64URL>` | Base64url WebAuthn credential id (16-64 raw bytes); import mode, requires the other three below |
| `--public-key <B64URL>` | Base64url-encoded 65-byte uncompressed SEC1 P-256 public key (`0x04 \|\| X \|\| Y`); import mode only |
| `--rp-id <HOSTNAME>` | Must match the profile's `[remote_approval] rp_id` exactly; import mode only |
| `--label <LABEL>` | Operator-chosen name for the credential (e.g. `"laptop"`); required in import mode, optional page pre-fill in interactive mode |
| `--sign-count <U32>` | Best-effort sign-counter seed read at enrollment time; import mode only (interactive mode extracts it automatically). Advisory only — never affects authorization |

```bash
# Local or SSH-tunnelled listener
stellar-agent approve operator enroll --interactive --label laptop

# Domain-configured remote listener: import a credential enrolled via its own /enroll page
stellar-agent approve operator enroll --credential-id <B64URL> \
  --public-key <B64URL> --rp-id wallet.example.internal --label laptop --sign-count <N>
```

---

## audit

Verifies the per-profile audit log, an append-only hash-chained JSONL record of every tool invocation and lifecycle event. Argument values are never logged; only argument key names. The chain links each entry to the SHA-256 of the prior entry's canonical body. Uses the `{ok, data, request_id}` envelope.

### `audit verify <LOG_PATH>`

Read-only. Walks the log at `<LOG_PATH>`, following rotation manifests, and verifies the hash chain end to end. With `--profile`, also loads that profile's audit chain-root HMAC key and verifies the chain-root sidecars; without it, only the hash chain is checked and `hmac_verified` is `false`.

| Flag / arg | Meaning |
|---|---|
| `<LOG_PATH>` (positional, required) | Path to the audit log file. Default location by OS: Linux `~/.local/share/stellar-agent/audit/<profile>.jsonl`; macOS `~/Library/Application Support/Soneso.stellar-agent/audit/<profile>.jsonl`; Windows `%LOCALAPPDATA%\Soneso\stellar-agent\data\audit\<profile>.jsonl` |
| `--profile <NAME>` | Profile whose chain-root HMAC key verifies sidecars |
| `--output <FORMAT>` | `json` is the default and only stable format |

On Unix, refuses to verify a log whose parent directory is owned by a different user. Exits `0` when the chain is intact, `1` on any integrity violation (broken chain, rotation gap, HMAC mismatch, missing sidecar, unparseable line), path-contract failure, or I/O error.

```bash
stellar-agent audit verify ~/.local/share/stellar-agent/audit/default.jsonl --profile default
```

```json
{"ok":true,"data":{"entries_verified":42,"files_walked":2,"hmac_verified":true,"per_file":[],"warnings":[],"audit_writer_degraded":false},"request_id":"..."}
```

### Governance loop

1. The agent surface evaluates an action against the policy engine; an action needing consent records a pending approval and returns its nonce instead of executing.
2. The wallet owner runs `approve --id <NONCE>`, reads the wallet-controlled summary, and consents; an HMAC attestation (or toolset grant) is written, bound to the nonce, the executed envelope's hash, and the local user.
3. The agent surface verifies the attestation and executes; every invocation is appended to the hash-chained log.
4. The operator periodically runs `audit verify --profile <NAME>` to confirm the chain (and chain-root HMAC sidecars) are intact.

---

## toolsets

Install, list, run, and uninstall agent toolsets with cryptographic provenance verification. Uses the standard `{ok, data|error, request_id}` envelope; failures carry a `toolsets.*` (directory/install/uninstall) or `toolset.*` (enforcement, shared with the MCP `stellar_toolset_invoke` tool) wire code. JSON by default. All four accept `--toolsets-dir <PATH>` to override the OS-conventional toolsets root. The binary subcommand is `toolsets` (plural).

### `toolsets install <PKG@VERSION> [flags]`

Installs a toolset from a signed local `.tar.gz`. The publisher key must be in the configured publisher trust set. Toolsets that declare a key-touching capability (e.g. `sign-payment`) additionally require a valid auditor attestation unless `--override-attestation`.

| Flag / arg | Meaning |
|---|---|
| `<PKG@VERSION>` (positional, required) | `<name>@<version>`, e.g. `my-toolset@1.0.0` |
| `--file <PATH>` (required) | Path to the `.tar.gz` package |
| `--shasum <HEX>` (required) | Expected SHA-256 of the package (64 lowercase hex) |
| `--signature <HEX>` (required) | Publisher ed25519 signature over the canonical preimage (128 hex = 64 bytes) |
| `--publisher <G-STRKEY>` (required) | Publisher ed25519 public key as a Stellar G-strkey |
| `--trust-set <PATH>` | Publisher trust-set file (default `<toolsets_dir>/trust.txt`) |
| `--attestation-file <PATH>` | JSON `ToolsetAttestation` from the auditor tool; required for key-touching toolsets unless overridden |
| `--auditor-trust-set <PATH>` | Auditor trust-set file (default `<toolsets_dir>/auditor-trust.txt`); distinct from the publisher set; an absent/empty set fails closed for key-touching toolsets |
| `--override-attestation` | Bypass the attestation gate for a key-touching toolset (the only sanctioned bypass); installs with the key-touching capability inert; reports `"attestation":"overridden"` |
| `--force` | Reinstall even if already installed |
| `--allow-downgrade` | Allow installing an older version over a newer one (only with `--force`) |
| `--toolsets-dir <PATH>` | Override toolsets root |

On success `data` carries `package`, `version`, and `attestation` (`"attested"` / `"overridden"` / `"not-required"` — the actual gate decision, not an inference from flags). Refusals (attestation-required, auditor-untrusted — no partial install — or any other install failure) carry `error.code` `toolsets.install_failed`, with the distinguishing detail in `error.message`.

```bash
stellar-agent toolsets install my-toolset@1.0.0 --file ./my-toolset-1.0.0.tar.gz \
  --shasum <sha256hex> --signature <128hex> --publisher GPUB...WXYZ
```

### `toolsets list [--toolsets-dir PATH]`

Read-only. The canonical scriptable enumeration of installed toolsets and their capability-derived action lists (not parsed from `--help`). Reports `data.toolsets`.

### `toolsets run <TOOLSET-NAME> <ACTION> [--toolsets-dir PATH]`

Runs the four-part capability enforcement check for an installed toolset action and reports the resolved trusted tool name. It does **not** execute the routed tool — use the MCP surface tool `stellar_toolset_invoke` for execution.

- `<TOOLSET-NAME>` (positional, required) — installed toolset package name.
- `<ACTION>` (positional, required) — must be an exact registry tool name the toolset's capabilities grant, e.g. `stellar_balances`.

On success, exit `0` with `data` carrying `toolset`, `action`, `routed_to`, and a `note` clarifying that enforcement passed but the tool was not run. On failure, exit `1` with `error.code`: `toolset.not_installed`, `toolset.unknown_action`, `toolset.capability_not_declared`, `toolset.tool_not_allowed`, `toolset.io_error`, or `toolset.error`. The toolset gate is additive: the routed tool's operator policy and chain gates still apply at execution time.

```bash
stellar-agent toolsets run balance-reporter stellar_balances
```

### `toolsets uninstall <PACKAGE> [--toolsets-dir PATH]`

Removes the toolset directory and pin record; refuses if not installed (`toolsets.uninstall_failed`). `<PACKAGE>` (positional, required) is the package name (`[a-z0-9-]`). On success `data` carries `package`.

```bash
stellar-agent toolsets uninstall my-toolset
```
