# CLI reference: accounts and core Stellar operations

This page documents the everyday Stellar operations exposed by the `stellar-agent` CLI: creating and funding accounts, deploying a smart-account contract, sending payments, reading balances, managing trustlines, funding via Friendbot, reading fee statistics, and managing the counterparty resolution cache.

The binary is `stellar-agent`. It is also discoverable as a `stellar-cli` plugin, so when `stellar` is installed the same command runs as `stellar agent <command> ...`. The examples here use the direct form.

Conventions shared by every command — profile resolution, the `--output` format, the JSON envelope and exit codes, the signer-source group, and the mainnet-write refusal — are defined once in the [CLI reference index](index.md). This page references that index for the shared flags and documents only what is specific to each command.

For the concepts referenced below (profiles, the policy engine, the approval spine, the audit log), see [concepts](../concepts.md). For SEP-29 memo enforcement and the counterparty `stellar.toml` resolution, see [protocols](../protocols.md).

## Shared flags

Several flags recur across the commands on this page with the same meaning. Their full description lives in the [global conventions](index.md#global-conventions) section of the index:

- `--profile <NAME>` — selects the [profile](../concepts.md). On the commands here it defaults to `"default"` (`accounts deploy-c` and `fees stats` instead default to no profile); none of these commands consult `STELLAR_AGENT_PROFILE`. Each command's table states its own default.
- `--network <NETWORK>` — `testnet` (default) or `mainnet`, case-insensitive. Write and signing commands structurally refuse `mainnet`; see [Mainnet-write refusal](index.md#mainnet-write-refusal).
- `--rpc-url <URL>` — the Soroban RPC endpoint. Default `https://soroban-testnet.stellar.org` where applicable.
- `--output <FORMAT>` — `json` (default) or `table`.
- `--timeout-seconds <SECONDS>` — bounds submission. Default `60`.
- Signer source — `--secret-env <VAR>` / `--deployer-secret-env <VAR>` (an env-var name, never the secret) or `--sign-with-ledger`, with `--account-index <INDEX>` for the Ledger derivation path (default `0`).
- `--fee <STROOPS|auto[:pNN]>` — the classic per-operation fee. An integer sets an explicit stroop value; `auto` selects the p95 percentile from `getFeeStats`; `auto:pNN` selects an explicit percentile (`p50`, `p75`, `p95`, `p99`). When absent, the profile default (100 stroops) applies. For Soroban operations the resource fee is set by simulation and is additional to this base.

Every command prints one JSON envelope on stdout by default and exits `0` on success, `1` on any error.

## `stellar-agent accounts`

Account-management group. Subcommands: `create`, `deploy-c`.

### `stellar-agent accounts create [NEW_G_STRKEY] [flags]`

Creates a new Stellar account in one of two mutually exclusive modes: a sponsored `CreateAccount` operation, or Friendbot funding.

- **Signing.** Sponsored mode signs the `CreateAccount` operation with the sponsor's key. Friendbot mode performs no signing and touches no key.
- **Policy (sponsored mode only).** After `--starting-balance` and the new account's public key are resolved and before signing, the sponsored `CreateAccount` is evaluated against `--profile`'s policy engine — the same evaluation the `stellar_create_account` MCP tool runs. With no persisted `<name>.toml` profile, an in-memory `Noop`-engine testnet profile is synthesized, so sponsored mode works without an authored profile file until an operator opts into `policy.engine = "v1"`. Friendbot mode is not gated: it debits no wallet-held funds.
- **Network.** `--network` accepts `testnet` or `mainnet`; `mainnet` is structurally refused before any RPC, HTTP, or key access. Sponsored mode returns `network.mainnet_write_forbidden`; Friendbot mode returns `network.friendbot_mainnet_forbidden`. Friendbot funding is testnet-only.
- **Account identity.** Provide the new account's G-strkey as the positional argument, or pass `--generate` to mint a fresh ed25519 keypair in-process. Exactly one is required.
- **Secret-key discipline.** `--generate` returns the new S-strkey in the JSON envelope's `data.secret_key` field. It is never emitted in `--output table` and never logged. Capture it from the JSON output and store it securely; for example, redirect with a restrictive umask: `umask 077 && stellar-agent accounts create --generate ... > secret.json`.

Argument groups (enforced by the parser):

- Mode (required, exactly one): `--sponsor` xor `--fund-with-friendbot`.
- Account (required, exactly one): positional `<NEW_G_STRKEY>` xor `--generate`.
- Signer (sponsored mode): `--secret-env` xor `--sign-with-ledger`.

| Flag / arg | Meaning | Required | Default |
|---|---|---|---|
| `<NEW_G_STRKEY>` (positional) | G-strkey of the account to create | one of the account group | — |
| `--generate` | Generate a fresh ed25519 keypair in-process; returns the G- and S-strkey in JSON | one of the account group | `false` |
| `--profile <NAME>` | Profile to evaluate operator policy against (sponsored mode only) | optional | `default` |
| `--sponsor <G_STRKEY>` | Sponsor/source account for the `CreateAccount` op | one of the mode group | — |
| `--starting-balance <AMOUNT>` | Starting balance with explicit units, e.g. `"5 XLM"` (bare numbers rejected) | sponsored mode | — |
| `--secret-env <VAR>` | Env-var name holding the sponsor S-strkey | signer group (sponsored) | — |
| `--sign-with-ledger` | Sign with a connected Ledger | signer group (sponsored) | `false` |
| `--account-index <INDEX>` | Ledger BIP-32 account index | optional | `0` |
| `--fund-with-friendbot` | Fund the account via Friendbot (testnet only) | one of the mode group | `false` |
| `--friendbot-url <URL>` | Friendbot endpoint URL (Friendbot mode) | optional | `https://friendbot.stellar.org` |
| `--network <NETWORK>` | Target network; `testnet` or `mainnet` (`mainnet` parses but is structurally refused for writes) | optional | `testnet` |
| `--fee <STROOPS\|auto[:pNN]>` | Classic per-op fee (sponsored mode) | optional | profile default (100) |
| `--timeout-seconds <SECONDS>` | Submission timeout (sponsored mode) | optional | `60` |
| `--rpc-url <URL>` | Soroban RPC endpoint (sponsored mode) | optional | `https://soroban-testnet.stellar.org` |
| `--output <FORMAT>` | `json` or `table` | optional | `json` |

The sponsor's public key must match the public key derived from the signer; a mismatch fails before submission.

Example — generate a new keypair and create it under a sponsor:

```bash
export SPONSOR_SK="S..."   # sponsor account secret key
stellar-agent accounts create \
  --generate \
  --sponsor GABC...WXYZ \
  --secret-env SPONSOR_SK \
  --starting-balance "5 XLM"
```

### `stellar-agent accounts deploy-c [flags]`

Deploys a new OpenZeppelin smart-account (C-account) contract instance on Soroban via `CreateContractV2`. The genesis signer is installed through the contract's `__constructor`.

- **Signing.** Signs the transaction's source-account credentials with the deployer key. The exception is `--dry-run`, which derives the resulting C-strkey deterministically with no signing and no RPC traffic.
- **Network.** `--network` accepts `testnet` or `mainnet`; `mainnet` is structurally refused (`network.mainnet_write_forbidden`) before any RPC or key access, with a passphrase-layer refusal at submit as defence in depth.
- **Salt.** The salt determines the deployed C-strkey. By default a fresh random 32-byte salt is generated. Pass `--salt-hex` to re-derive a known address (for example, recovery or interop verification); the same deployer plus the same salt always recovers the same C-strkey.
- **Audit.** Pass `--profile` to route deployment entries to that profile's audit-log writer. When omitted, the handler emits no `deploy-c` audit entries.
- **Genesis signer source.** Exactly one signer is installed at genesis — `__constructor` takes a single-element `Vec<Signer>`. Four mutually exclusive sources cover this: a Delegated (native) G-key, an already-registered WebAuthn passkey by name, a raw External-Ed25519 public key, or a generic External signer against any registered verifier contract. Only the Delegated source is fail-open by default; the other three require an explicit acknowledgement flag because the resulting account has no built-in G-key fallback until a second signer is added post-deploy.

Argument groups (enforced by the parser):

- Deployer (required, exactly one): `--deployer-secret-env` xor `--sign-with-ledger`.
- Salt (at most one): `--salt-hex` xor `--salt-random`; defaults to random when neither is given.
- Genesis signer source (required, exactly one): `--initial-signer` xor `--signer-webauthn` xor `--signer-ed25519` xor `--signer-external` (with `--signer-key-data`).

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--initial-signer <G_STRKEY>` | Delegated (native) genesis signer | one of the genesis-signer group | — |
| `--signer-webauthn <CREDENTIAL_NAME>` | Genesis signer is an already-registered WebAuthn passkey, looked up by name in the local passkeys registry; requires a WebAuthn verifier already deployed for the target network (`smart-account deploy-webauthn-verifier`) | one of the genesis-signer group | — |
| `--signer-ed25519 <HEX_PUBKEY_64>` | Genesis signer is a raw 32-byte ed25519 public key (64 hex chars), verified by the Ed25519 verifier resolved from `--verifier` when supplied, else from the verifier registry | one of the genesis-signer group | — |
| `--verifier <C_STRKEY>` | Ed25519-verifier contract override for `--signer-ed25519`. Omitted, it resolves from the verifier registry (populated by `smart-account deploy-ed25519-verifier`), failing closed if none is registered | with `--signer-ed25519` | registry lookup |
| `--signer-external <C_STRKEY>` | Genesis signer is verified by this verifier contract; requires `--signer-key-data` | one of the genesis-signer group | — |
| `--signer-key-data <HEX>` | Verifier-specific key material for `--signer-external` | required with `--signer-external` | — |
| `--accept-no-delegated-fallback` | Acknowledges that `--signer-webauthn` / `--signer-ed25519` / `--signer-external` leaves the account with NO Delegated (G-key) fallback signer at genesis; refused without this flag (`validation.passkey_only_rule_no_delegated_fallback`) | required with a non-Delegated genesis source | `false` |
| `--deployer-secret-env <VAR>` | Env-var name holding the deployer S-strkey | one of the deployer group | — |
| `--sign-with-ledger` | Use a Ledger as the deployer | one of the deployer group | `false` |
| `--account-index <INDEX>` | Ledger BIP-44 account index | optional | `0` |
| `--salt-hex <HEX64>` | 32-byte salt as 64-char lowercase hex (re-deploy at a known C-strkey) | one of the salt group | — |
| `--salt-random` | Generate a fresh random 32-byte salt | one of the salt group | random when `--salt-hex` absent |
| `--profile <NAME>` | Profile whose audit writer receives deploy entries | optional | none |
| `--network <NETWORK>` | Target network; `testnet` or `mainnet` (`mainnet` parses but is structurally refused for writes) | optional | `testnet` |
| `--rpc-url <URL>` | Soroban RPC endpoint | optional | `https://soroban-testnet.stellar.org` |
| `--fee <STROOPS\|auto[:pNN]>` | Classic per-op fee; see [Shared flags](#shared-flags) | optional | profile default (100) |
| `--timeout-seconds <SECONDS>` | Submission timeout | optional | `60` |
| `--output <FORMAT>` | `json` or `table` | optional | `json` |
| `--dry-run` | Derive the C-strkey only; no signing, no RPC | optional | `false` |

The deployer account must be funded; it pays the deployment fee.

A genesis signer that is not Delegated cannot itself authorize any further rule mutation (`smart-account rules`, `smart-account signers`) on the account: `add_signer` / `batch_add_signers` / rule installs authorize only via a Delegated signer's key. Deployments using `--signer-webauthn` / `--signer-ed25519` / `--signer-external` should follow up promptly with `smart-account signers add` to attach a Delegated co-signer capable of administering the account, once a policy is attached to the target rule (see [`smart-account rules add-policy`](smart-account.md#smart-account-rules-add-policy) and [`smart-account signers add`](smart-account.md#smart-account-signers-add)).

Example — deploy with a random salt, signing from an env-var secret:

```bash
export DEPLOYER_SK="S..."   # deployer account secret key
stellar-agent accounts deploy-c \
  --initial-signer GABC...WXYZ \
  --deployer-secret-env DEPLOYER_SK \
  --salt-random
```

Example — deploy with a registered WebAuthn passkey as the sole genesis signer:

```bash
export DEPLOYER_SK="S..."   # deployer account secret key
stellar-agent accounts deploy-c \
  --signer-webauthn my-passkey \
  --accept-no-delegated-fallback \
  --deployer-secret-env DEPLOYER_SK \
  --salt-random
```

## `stellar-agent pay <DESTINATION> <AMOUNT> [ASSET] [flags]`

Sends a payment from a source account to a destination, enforcing SEP-29 memo-required before signing (see [protocols](../protocols.md)).

- **Signing.** By default the command builds, signs, and submits atomically. Three staged flags split the pipeline: `--build-only` emits the unsigned envelope XDR and exits (no signing); `--sign-only <XDR>` signs a prebuilt envelope and emits signed XDR; `--submit-only <XDR>` submits a pre-signed envelope. The stage flags are mutually exclusive.
- **Policy.** After the envelope is built and before signing (in both the full pipeline and `--build-only`), the amount/asset/destination are evaluated against `--profile`'s policy engine — the same evaluation the `stellar_pay` MCP tool runs. With no persisted `<name>.toml` profile, an in-memory `Noop`-engine testnet profile is synthesized, so the command works without an authored profile file until an operator opts into `policy.engine = "v1"`. The staged `--sign-only` and `--submit-only` flows are gated too: each decodes the supplied envelope through the same decoder the MCP `stellar_pay_commit` path uses and evaluates the decoded amount/asset/destination before signing (`--sign-only`) or before broadcasting (`--submit-only` — the envelope arrives pre-signed, but broadcasting still spends funds). An envelope the decoder cannot classify into a sized shape follows the opaque-signing posture: under a matched value rule it denies `policy.deny.unsizable_value_effect` unless the rule sets `allow_opaque_signing = true`. The staged flows match policy rules under the `stellar_pay_commit` tool name (the same name the MCP commit phase matches); a ruleset that names only `stellar_pay` default-denies them, so author rules for both names, or `tool = "*"`, for uniform behavior. Under `policy.engine = "noop"` the staged flows are ungated, matching the rest of the command.
- **Network.** `--network` accepts `testnet` or `mainnet`; `mainnet` returns `network.mainnet_write_forbidden` before any RPC call, with a submit-layer URL rejection as defence in depth.
- **Relayer.** `--use-oz-relayer` is not implemented in this build. Passing it emits an AGPL-3.0 disclosure to stderr and declines the operation rather than submitting.

Argument groups (enforced by the parser):

- Stage (at most one): `--build-only` / `--sign-only` / `--submit-only`.
- Memo (at most one): `--memo-text` / `--memo-id` / `--memo-hash` / `--memo-return`.
- Signer (at most one): `--secret-env` xor `--sign-with-ledger`.

| Flag / arg | Meaning | Required | Default |
|---|---|---|---|
| `<DESTINATION>` (positional) | Destination account G-strkey | yes | — |
| `<AMOUNT>` (positional) | Amount with explicit units, e.g. `"10 XLM"`, `"10.5 USDC"` (raw stroop strings rejected) | yes | — |
| `[ASSET]` (positional) | `native`, `XLM`, or `CODE:ISSUER_GSTRKEY` | optional | `native` |
| `--profile <NAME>` | Profile to evaluate operator policy against | optional | `default` |
| `--source <G_STRKEY>` | Source account; required for signing | conditional | — |
| `--memo-text <STRING>` | Memo text (UTF-8, up to 28 bytes) | one of the memo group | — |
| `--memo-id <U64>` | Memo ID (u64 decimal) | one of the memo group | — |
| `--memo-hash <64_HEX>` | Memo hash (64 hex chars / 32 bytes) | one of the memo group | — |
| `--memo-return <64_HEX>` | Memo return hash (64 hex chars / 32 bytes) | one of the memo group | — |
| `--secret-env <VAR>` | Env-var name holding the source S-strkey | signer group | — |
| `--sign-with-ledger` | Sign with a connected Ledger | signer group | `false` |
| `--account-index <INDEX>` | Ledger BIP-32 account index | optional | `0` |
| `--build-only` | Emit the unsigned envelope XDR and exit | stage group | `false` |
| `--sign-only <BASE64_XDR>` | Sign the given XDR, emit signed XDR | stage group | — |
| `--submit-only <BASE64_XDR>` | Submit the given signed XDR | stage group | — |
| `--fee <STROOPS\|auto[:pNN]>` | Classic per-op fee | optional | profile default (100) |
| `--network <NETWORK>` | Target network; `testnet` or `mainnet` (`mainnet` parses but is structurally refused for writes) | optional | `testnet` |
| `--timeout-seconds <SECONDS>` | Submission timeout | optional | `60` |
| `--rpc-url <URL>` | Soroban RPC endpoint | optional | `https://soroban-testnet.stellar.org` |
| `--output <FORMAT>` | `json` or `table` | optional | `json` |
| `--use-oz-relayer` | Opt into the OZ Relayer path (not implemented; declines) | optional | `false` |

Example — send 10 XLM with a text memo:

```bash
export WALLET_SK="S..."   # source account secret key
stellar-agent pay GDEST...WXYZ "10 XLM" \
  --source GSRC...WXYZ \
  --secret-env WALLET_SK \
  --memo-text "invoice-42"
```

## `stellar-agent claim <BALANCE_ID> [flags]`

Claims a classic claimable balance by its ID, after an RPC-backed pre-flight:
the entry is fetched via `getLedgerEntries`, a typed preview is rendered
(asset, amount, claimants, clawback flag, predicate verdict with the
claimability window), and the command refuses before signing unless the source
account is a claimant (`claim.not_claimant`), the claimant's predicate is
currently satisfied (`claim.predicate_not_satisfied`), and — for a non-native
asset — an authorized trustline with enough limit headroom exists
(`claim.trustline_missing` / `claim.trustline_not_authorized` /
`claim.trustline_limit`).

- **Balance ID forms.** The canonical 72-hex form (eight-`0` V0 prefix plus the
  64-hex hash), the bare 64-hex hash, or the `B...` strkey. Any non-V0
  discriminant is rejected (`claim.invalid_balance_id`).
- **Listing is out of scope.** Stellar RPC cannot enumerate claimable balances
  by claimant; the ID arrives out-of-band (from the sender, an anchor
  response, or the creating transaction's result).
- **Signing.** Same staged pipeline as `pay`: atomic by default;
  `--build-only` / `--sign-only <XDR>` / `--submit-only <XDR>` split it.
- **Policy.** After the build stage (guards, preview, envelope construction)
  and before signing (in both the full pipeline and `--build-only`), the claim
  is evaluated against `--profile`'s policy engine — the same evaluation the
  `stellar_claim` MCP tool runs. With no persisted `<name>.toml` profile, an
  in-memory `Noop`-engine testnet profile is synthesized, so the command works
  without an authored profile file until an operator opts into
  `policy.engine = "v1"`. The staged `--sign-only` and `--submit-only` flows are
  gated too: each decodes the supplied envelope through the same decoder the
  MCP `stellar_claim_commit` path uses and evaluates it before signing
  (`--sign-only`) or before broadcasting (`--submit-only` — the envelope
  arrives pre-signed, but broadcasting still spends funds). An envelope the
  decoder cannot classify into a sized shape follows the opaque-signing
  posture: under a matched value rule it denies
  `policy.deny.unsizable_value_effect` unless the rule sets
  `allow_opaque_signing = true`. The staged flows match policy rules under the
  `stellar_claim_commit` tool name (the same name the MCP commit phase
  matches); a ruleset that names only `stellar_claim` default-denies them, so
  author rules for both names, or `tool = "*"`, for uniform behavior. Under
  `policy.engine = "noop"` the staged flows are ungated, matching the rest of
  the command.
- **Network.** `--network` accepts `testnet` or `mainnet`; `mainnet` returns
  `network.mainnet_write_forbidden` before any RPC call.
- **Timing.** The predicate is evaluated against the local clock; on-chain
  validation uses the apply-ledger close time, so a claim previewed near a
  time-bound boundary can still fail on submit.

| Flag / arg | Meaning | Required | Default |
|---|---|---|---|
| `<BALANCE_ID>` (positional) | Claimable balance ID (72-hex, 64-hex, or `B...` strkey) | yes | — |
| `--profile <NAME>` | Profile to evaluate operator policy against | optional | `default` |
| `--source <G_STRKEY>` | Claiming account; must be a claimant | yes | — |
| `--secret-env <VAR>` | Env-var name holding the source S-strkey | signer group | — |
| `--sign-with-ledger` | Sign with a connected Ledger | signer group | `false` |
| `--account-index <INDEX>` | Ledger BIP-32 account index | optional | `0` |
| `--build-only` | Emit the unsigned envelope XDR and exit | stage group | `false` |
| `--sign-only <BASE64_XDR>` | Sign the given XDR, emit signed XDR | stage group | — |
| `--submit-only <BASE64_XDR>` | Submit the given signed XDR | stage group | — |
| `--fee <STROOPS\|auto[:pNN]>` | Classic per-op fee | optional | profile default (100) |
| `--network <NETWORK>` | Target network; `testnet` or `mainnet` (`mainnet` parses but is structurally refused for writes) | optional | `testnet` |
| `--timeout-seconds <SECONDS>` | Submission timeout | optional | `60` |
| `--rpc-url <URL>` | Soroban RPC endpoint | optional | `https://soroban-testnet.stellar.org` |
| `--output <FORMAT>` | `json` or `table` | optional | `json` |

Example — claim a balance received from a payment sender:

```bash
export WALLET_SK="S..."   # claiming account secret key
stellar-agent claim BAAD...R4TU \
  --source GABC...WXYZ \
  --secret-env WALLET_SK
```

## `stellar-agent balances [flags]`

Reads the native XLM balance and trustlines for an account via the Stellar RPC `getLedgerEntries`.

- **Signing.** Read-only; no signing or key access.
- **Network.** No mainnet gate; the command queries whatever `--rpc-url` points at.
- **Account.** `--account` is required in practice. When omitted the command exits `1` (the active-profile fallback is not wired).
- **Trustlines.** Pass `--asset CODE:ISSUER` to query specific trustlines; repeat the flag for multiple assets. Assets the account does not trust are silently omitted from the output.

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--account <G_STRKEY>` | Account to query | required in practice | — |
| `--asset <CODE:ISSUER>` | Trustline asset to query; repeatable | optional | none |
| `--rpc-url <URL>` | Stellar RPC endpoint | optional | `https://soroban-testnet.stellar.org` |
| `--output <FORMAT>` | `json` or `table` | optional | `json` |

Example — read XLM plus a USDC trustline:

```bash
stellar-agent balances \
  --account GABC...WXYZ \
  --asset USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN
```

## `stellar-agent trustline [flags]`

Creates or removes a classic trustline (`ChangeTrust`) behind an ordered trust gate: operator policy evaluation, denomination resolution (USDT hard-refusal plus a known-lookalike denylist and pinned-issuer checks), a live issuer-flag fetch that fail-closes on error, a clawback gate, and a typed preview, before the envelope is built, signed, and submitted.

- **Signing.** Signs via the profile's keyring signer; builds, signs, submits, and waits atomically. There is no staged pipeline.
- **Network.** Derived from the loaded profile (`rpc_url`, `network_passphrase`, `chain_id`). `--chain-id` overrides the CAIP-2 value. There is no `--network` flag and no built-in mainnet refusal here; the network is governed by the profile configuration.
- **USDT is hard-refused.** The denomination resolver rejects USDT outright; the command cannot create a USDT trustline.
- **Limit.** `--limit-stroops 0` removes the trustline. When absent the Stellar default (`i64::MAX`, unlimited) applies.
- **Asset grammar.** A bare code such as `USDC` resolves through the pin table; `CODE:ISSUER` names an explicit issuer; a 56-char `C...` SAC address is deferred and returns a typed error.

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--from <G_STRKEY>` | Account that will hold the trustline | yes | — |
| `--asset <ASSET>` | `USDC` (bare, pin table), `CODE:ISSUER`, or a `C...` SAC address (deferred) | yes | — |
| `--limit-stroops <I64>` | Explicit trustline limit; `0` removes the trustline | optional | unlimited (`i64::MAX`) |
| `--profile <NAME>` | Profile to load | optional | `default` |
| `--chain-id <CAIP2>` | CAIP-2 chain id, e.g. `stellar:testnet` | optional | profile value |
| `--fee <STROOPS\|auto[:pNN]>` | Classic per-op fee | optional | profile `classic_fee_per_op_stroops` |

Example — establish a USDC trustline:

```bash
stellar-agent trustline \
  --from GABC...WXYZ \
  --asset USDC \
  --profile default
```

## `stellar-agent friendbot [flags]`

Funds a testnet or futurenet account via the Stellar Friendbot HTTP endpoint.

- **Signing.** No local signing or key access; Friendbot funds the account.
- **Network.** `--network` accepts `testnet`, `futurenet`, or `mainnet` at the parser, but `mainnet` is structurally refused at dispatch with `network.friendbot_mainnet_forbidden` before any HTTP call. The endpoint URL is validated against an allow-list (`friendbot.stellar.org`, `friendbot-futurenet.stellar.org`) unless `--friendbot-url-unchecked` is set.
- **Funding verification.** After a successful Friendbot HTTP response, the command polls `--rpc-url` until the funded account is queryable before reporting success. The JSON envelope's `data.funding_confirmed_after_ms` reports how long that took. If the account never becomes queryable, the command exits `1` with `network.friendbot_funding_not_confirmed` rather than reporting a Friendbot HTTP success that has not actually landed.

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--account <G_STRKEY>` | Account to fund | yes | — |
| `--network <NETWORK>` | `testnet`, `futurenet`, or `mainnet` (mainnet refused at dispatch) | optional | `testnet` |
| `--friendbot-url <URL>` | Override the Friendbot endpoint URL; when omitted, resolves at runtime to the SDF testnet URL (`https://friendbot.stellar.org`) regardless of `--network`, so `futurenet` needs an explicit override | optional | `https://friendbot.stellar.org` (testnet) |
| `--friendbot-url-unchecked` | Bypass the URL allow-list (development/test escape hatch) | optional | `false` |
| `--rpc-url <URL>` | Soroban RPC endpoint used to verify that funding landed; the default follows `--network` so the verification queries the network the funding targeted | optional | derived from `--network` (`https://soroban-testnet.stellar.org` / `https://rpc-futurenet.stellar.org`) |
| `--output <FORMAT>` | `json` or `table` | optional | `json` |

Example — fund a testnet account:

```bash
stellar-agent friendbot --account GABC...WXYZ --network testnet
```

## `stellar-agent fees`

Fee-statistics group. Subcommand: `stats`.

### `stellar-agent fees stats [flags]`

Fetches Stellar RPC fee statistics, the helper behind classic fee selection.

- **Signing.** Read-only; no signing or key access.
- **Network.** No mainnet gate. The RPC endpoint resolves in order: `--rpc-url`, then the profile's `rpc_url` (via `--profile`), then the testnet default. When `--rpc-url` is given it is validated against the allow-list.

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--profile <NAME>` | Profile whose RPC URL to use | optional | none (falls back to testnet default) |
| `--rpc-url <URL>` | Allow-listed RPC endpoint override | optional | `https://soroban-testnet.stellar.org` |
| `--output <FORMAT>` | `json` or `table` | optional | `json` |

Example — print fee stats as a table:

```bash
stellar-agent fees stats --output table
```

## `stellar-agent counterparty`

Manages the per-profile cache of `stellar.toml` bindings that backs the counterparty allowlist policy (see [concepts](../concepts.md) and [protocols](../protocols.md)). None of these subcommands sign a Stellar transaction.

Cache files live under the OS-conventional local data directory for the profile, for example `~/Library/Application Support/Soneso.stellar-agent/counterparty/<profile>/` on macOS, `~/.local/share/stellar-agent/counterparty/<profile>/` (or `$XDG_DATA_HOME/stellar-agent/counterparty/<profile>/`) on Linux, and `%LOCALAPPDATA%\Soneso\stellar-agent\data\counterparty\<profile>\` on Windows. Each binding is HMAC-protected with the per-profile cache key; entries that fail verification are skipped on read.

Subcommands: `list`, `refresh`, `evict`, `warm-up`, `rotate-hmac-key`.

### `stellar-agent counterparty list [flags]`

Lists the cached bindings for a profile — home domain plus fetched and expiry timestamps. Entries whose HMAC fails verification are silently skipped. Read-only (local cache read).

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--profile <NAME>` | Profile whose cache to list | optional | `default` |
| `--json` | Emit the canonical JSON envelope (JSON is the only shape; the flag is a no-op for scripting compatibility) | optional | `false` |

```bash
stellar-agent counterparty list --profile default
```

### `stellar-agent counterparty refresh <HOME_DOMAIN> [flags]`

Force-fetches `https://<home-domain>/.well-known/stellar.toml`, HMAC-protects the body, and writes it to the cache atomically. Performs a network fetch and a keyring write; signs no transaction. The home domain must be strict ASCII, 1 to 32 characters; IDN and homoglyph domains are rejected to prevent counterparty-binding spoofing.

| Flag / arg | Meaning | Required | Default |
|---|---|---|---|
| `<HOME_DOMAIN>` (positional) | Domain to refresh (strict ASCII, 1-32 chars) | yes | — |
| `--profile <NAME>` | Profile whose cache to update | optional | `default` |

```bash
stellar-agent counterparty refresh circle.com --profile default
```

### `stellar-agent counterparty evict <HOME_DOMAIN> [flags]`

Deletes a single cached binding, leaving other domains untouched. Exits `0` even when the cache file was already absent. Performs a local file removal; signs no transaction.

| Flag / arg | Meaning | Required | Default |
|---|---|---|---|
| `<HOME_DOMAIN>` (positional) | Domain whose cache file to remove | yes | — |
| `--profile <NAME>` | Profile whose cache to update | optional | `default` |

```bash
stellar-agent counterparty evict circle.com --profile alice
```

### `stellar-agent counterparty warm-up [flags]`

Refreshes every `HOME_DOMAIN` entry currently configured in the profile's policy counterparty allowlist and prints a per-domain summary. Exits `1` if any refresh fails. Performs network fetches and HMAC writes; signs no transaction.

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--profile <NAME>` | Profile whose allowlist to refresh | optional | `default` |

```bash
stellar-agent counterparty warm-up --profile default
```

### `stellar-agent counterparty rotate-hmac-key [flags]`

Rotates the per-profile counterparty cache HMAC key. After rotation, existing cache files fail verification and must be refreshed. Rotates a keyring secret; signs no transaction. This is the same keyring entry (`counterparty_cache_key_id`) that `stellar-agent profile rotate-counterparty-key <NAME>` rotates (see [profile and governance](profile-and-governance.md)); the two verbs are interchangeable entry points to the same rotation.

| Flag | Meaning | Required | Default |
|---|---|---|---|
| `--profile <NAME>` | Profile whose cache HMAC key to rotate | optional | `default` |

```bash
stellar-agent counterparty rotate-hmac-key --profile default
```

## Related pages

- [CLI reference index](index.md)
- [Concepts](../concepts.md)
- [Protocols](../protocols.md)
