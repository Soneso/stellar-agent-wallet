# CLI reference

`stellar-agent` is a self-custodial Stellar wallet for AI agents. It builds, signs, and submits transactions on testnet under a policy engine, an operator-approval spine, and a tamper-evident hash-chained audit log.

This page covers the conventions shared by every command: how the profile and network are resolved, the signer-source flags, the JSON output envelope and exit codes, and the mainnet-write refusal. Each command group is documented on its own page, linked from the [command index](#command-index) below.

For the concepts referenced here (profiles, the policy engine, the approval spine, the audit log, context rules), see [concepts](../concepts.md). For which commands need only a classic keyring key versus a deployed smart-account contract, see [the two account models](../concepts.md#two-account-models).

## Invocation

The binary is installed as `stellar-agent` on your `PATH`. It is also discoverable as a `stellar-cli` plugin, so when `stellar` is installed it can be invoked as:

```bash
stellar agent <command> ...
```

Both forms run the same binary. The examples in this reference use the direct `stellar-agent` form.

Run `stellar-agent --help` for the live subcommand list, or `stellar-agent <command> --help` for a group's flags.

### Availability

The wallet is a public alpha; prebuilt binaries are published on the GitHub releases page for each tagged release, and all crates are published on crates.io. While only prerelease versions are published, the version must be spelled out — a bare crate name matches stable versions only. The ways to install are:

- `cargo binstall --locked --disable-strategies quick-install,compile stellar-agent-cli@0.1.0-alpha.10`: downloads the prebuilt GitHub release archive, resolved through crates.io. The archive is `stellar-agent-<version>-<target>.tar.xz`, or `.zip` on Windows. The `stellar-agent` CLI and the `stellar-agent-mcp` server ship in one archive. With the strategy flag, binstall fails on a host for which no release archive exists; see [Prebuilt binaries](../getting-started.md#prebuilt-binaries-cargo-binstall) for the release targets.
- `cargo install --locked stellar-agent-cli@0.1.0-alpha.10`: builds from the published sources with the `Cargo.lock` published in the crate and installs the binary `stellar-agent`.
- Building from a clone of the release tag with `cargo build --release --locked`.

## Global conventions

There are no flags on the top-level command. Network selection, the profile, RPC URLs, and the signer source are declared per subcommand. The recurring flags below have the same meaning everywhere they appear; the per-group pages reference this section rather than restating them.

### Profile

`--profile <NAME>` selects the [profile](../concepts.md) — the per-environment TOML config that binds a CAIP-2 chain, an RPC endpoint, keyring entry references, thresholds, and the active policy engine. A profile holds no secrets; it only names keyring entries.

The effective profile name is resolved in this order:

1. An explicit `--profile <NAME>` flag.
2. The `STELLAR_AGENT_PROFILE` environment variable.
3. The literal `"default"`.

A mainnet profile loads only through `--profile <name>`. `STELLAR_AGENT_PROFILE` never selects one, and a mainnet `default.toml` needs `--profile default`. Keep the filename: its identity is bound to its keyring entries.

Some commands take the profile as a positional argument instead of a flag (the `profile` group itself); those cases are noted on their page.

The selected name must also be the name the profile file carries. Every command that loads a profile compares the selected name against the one derived from the file's `policy_owner_key_id.service`, and refuses with `profile.name_mismatch` when the two disagree — the case a `<name>.toml` copied or renamed from another profile produces. The refusal names both profiles and quotes the offending field; recover with `stellar-agent profile init --profile <name>`, or by correcting that field to `stellar-agent-owner-<name>`. `stellar-agent profile show <name>` is the one command that still displays a mismatched profile, so the field can be read.

### Network

Transaction commands read the chain from the resolved profile. An unnamed, missing profile uses the zero-config testnet profile.
`--network <NETWORK>` optionally asserts `testnet` or `mainnet`, case-insensitive. A value differing from the profile refuses with `profile.network_flag_mismatch` before the command's structural mainnet refusal.

`balances` keeps its endpoint-based selection, standalone `friendbot` keeps its testnet-class network selector, and `profile init --network` selects the chain for a new file.
`trustline` reads its chain from the profile.

### RPC endpoints

`--rpc-url <URL>` and `--secondary-rpc-url <URL>` are optional. Without a flag, each endpoint comes from the profile.
On testnet, a flag replaces its profile field. On mainnet, either flag refuses with `profile.non_overlayable_field`, including an equal value. The same code refuses environment and programmatic overlays outside their classes; see [Loader source order](../profiles.md#loader-source-order).
RPC URL flags refuse credentials. Configure credentialed endpoints in the profile.

Smart-account rule commands use the effective secondary for cross-RPC checks. `smart-account multicall` requires a secondary endpoint.
The signers manager and timelock commands use the primary when no secondary is configured.
`balances` keeps its testnet endpoint default. Standalone `friendbot` derives its endpoint from its network selector.
`fees stats --profile` applies the endpoint rules above and keeps its flag allowlist. Without `--profile`, it uses `--rpc-url`, else the testnet endpoint.

### Timeout

`--timeout-seconds <SECONDS>` bounds submission and simulation. The default is `60`.

### Output format

`--output <FORMAT>` accepts `json` (the default) or `table`. The `table` form is offered on some commands and deferred on others; where deferred, `json` is emitted regardless. A few commands do not accept `--output` at all (noted on their pages).

### Signer source

Signing commands take a mutually exclusive signer-source group. Exactly one source is selected:

- The secret-env flag: the name of an environment variable holding the source account S-strkey. Set the variable as [Pass a secret seed](../getting-started.md#pass-a-secret-seed) shows; pass the variable name, never the secret itself. Its spelling is `--secret-env` on `pay` and `accounts create`, `--deployer-secret-env` on `accounts deploy-c`, and `--signer-secret-env` on the `smart-account` commands; the per-group pages give the exact spelling.
- `--sign-with-ledger`: sign with a connected Ledger hardware device.
- `--account-index <INDEX>`: the BIP-44 account index for the Ledger derivation path. Default `0`.

Run this line on its own, paste the source-account seed when prompted, and press Enter:

```bash
printf 'WALLET_SK seed: ' && read -rs WALLET_SK && echo && export WALLET_SK
```

```bash
stellar-agent pay GDEST...WXYZ "10 XLM" --source GSRC...WXYZ --secret-env WALLET_SK
unset WALLET_SK
```

## Output envelope and exit codes

By default every command prints one JSON envelope on stdout. Exit code `0` means success; exit code `1` means any error. Scripts can branch on the exit code and parse the JSON for details.

```bash
if stellar-agent balances --account GABC...WXYZ > out.json; then
  jq '.' out.json
else
  echo "command failed" >&2
fi
```

## Mainnet-write refusal

The zero-config profile uses testnet. Friendbot funding is limited to testnet-class networks.

On a mainnet profile, `pay`, `claim`, account creation, account deployment, and smart-account deployment refuse before signer access.
The same structural refusal covers all signer verbs, rule writes, policy writes, `rules verify-pins` (it loads a signer), `execute`, migration submit, timelock writes, and `multicall`.
It also covers `vault deposit`, `vault withdraw`, `trade`, `trustline`, and `pool init`, before signer access and any RPC call.
It reports `network.mainnet_write_forbidden`; Friendbot funding reports `network.friendbot_mainnet_forbidden`, and `mpp` reports `mpp.network_forbidden`.
Read-only inspection remains available. `tx` signs nothing, and `pool init` is the only `pool` command that signs.
`--network` is checked against the profile before a structural refusal, so `--network mainnet` on the zero-config testnet profile reports `profile.network_flag_mismatch`.

The submit layer applies the same refusal in a fixed order. A declared mainnet network passphrase is refused first, then an `--rpc-url` matching a known mainnet host; both cost zero RPC calls. The envelope is then decoded locally, so a malformed or legacy V0 envelope is refused without a round trip.

## Submit-layer network binding

The submit layer does not take the declared network on trust. Before sending, it asks the endpoint which network it serves (`getNetwork`), on the same client instance that will send, and treats that answer, not the declaration, as authoritative:

- the endpoint reports mainnet: `network.mainnet_write_forbidden`;
- the endpoint reports a different network than the one declared: `network.endpoint_network_mismatch`;
- the endpoint's identity cannot be established within the submission timeout: `network.endpoint_identity_unavailable`.

The probe is retried with bounded exponential backoff inside the caller's own timeout and is fail-closed: it never falls back to the declared network. This is the one mainnet refusal that costs a round trip.

The layer then verifies the envelope's signatures against that network. It fetches the ed25519 signer sets of the transaction source account and of every distinct operation-level source account in one `getLedgerEntries` call (for a fee-bump, the fee source answers for the outer signatures and the inner transaction's sources for the inner ones); an account absent from the ledger is refused with `network.account_not_found` before anything is sent, unless the transaction itself creates it, in which case its own master key is the signer it will have at apply time and no ledger entry is needed. Every decorated signature must then verify: the SEP-23 signing payload is rebuilt under the network id the endpoint reported and checked against the gathered signers whose key hint matches.

- verifies under the endpoint's network id: accepted;
- verifies under the mainnet network id: `network.envelope_signed_for_mainnet`;
- verifies under neither: `network.envelope_signature_unverifiable`;
- the envelope carries no signature, or on a fee-bump the outer or the inner transaction carries none: `network.envelope_unsigned`.

Every signature must pass, and each signature set must have at least one: on a fee-bump the outer and the inner transaction are checked separately, so an outer signature cannot stand in for a missing inner one. Hash-x and pre-auth-tx signers contribute no ed25519 key, so a signature only such a signer could account for is refused. Two consequences follow. An envelope signed for one network cannot be submitted under another network's passphrase at either submit entry point, including from a library consumer of the published crate with no CLI involved. And the submit path performs two reads before it sends, so every submission makes two round trips before the send.

## Audit-key pre-flight refusal

Every value-moving signing verb (`pay`, `claim`, `accounts create` sponsored mode, `trustline`, `trade`, `lend`, `vault`) proves the active profile's audit chain-root key is acquirable BEFORE any signing key is touched or transaction submitted. A profile fresh from `profile init` has the audit-log keyring COORDINATE but no key material — `profile rotate-audit-key <name>` mints it. Until that runs, these verbs refuse with the wire code `audit.chain_key_unavailable` rather than signing unaudited. Build-only/simulate stages are unaffected: they neither sign nor submit, so they never reach this pre-flight. On `pay --submit-only` and `claim --submit-only` the endpoint identity probe runs on the command's own client ahead of the policy gate and ahead of this pre-flight, so an `--rpc-url` pointing at a different network than `--network` is refused before either one runs. This pre-flight fails closed only for a persisted `<name>.toml` profile: `pay`, `claim`, and `accounts create` keep their zero-config posture — the in-memory profile synthesized when no profile was named and no `default.toml` exists stays fail-open on this specific check. See [Key-rotation subcommands](profile-and-governance.md#key-rotation-subcommands) and [Concepts: fail-closed on an unminted audit key](../concepts.md#fail-closed-on-an-unminted-audit-key).

The same pre-flight proves the audit log still contains the chain tip its keyring-held anchor names, refusing with `audit.tip_anchor_mismatch` when the log was restored from an older copy, truncated, or substituted. A log that moved forward past its anchor is absorbed, not refused, and a log with no anchor is adopted on first use with no operator action. A profile whose `audit_log_path` or audit key differs from the binding recorded in the keyring refuses with `audit.log_binding_changed`. Recovery from either is [`audit reanchor`](profile-and-governance.md#audit-reanchor---profile-name---acknowledge-rollback).

## Startup advisory

Before dispatching any command, the CLI runs a local-only startup advisory: it scans the profile's audit log for context rules that reference revoked or retired verifier WASM hashes. The scan issues no network calls and is non-fatal. If it cannot run, the error is logged at warn level and the command proceeds. The advisory reads the audit log of the profile the command it precedes operates on: it takes the profile the parsed subcommand resolved and applies the same resolution order as that subcommand. The advisory therefore never opens — or appends to — a different profile's log than the command itself uses.

## Command index

| Command group | Purpose | Page |
|---|---|---|
| `smart-account` (alias `sa`) | Smart-account administration: context rules, signers, threshold, multicall, verifier and timelock infrastructure. | [smart-account](smart-account.md) |
| `accounts` | Create a Stellar account (sponsored `CreateAccount` or Friendbot) and deploy an OpenZeppelin smart-account contract. | [stellar-ops](stellar-ops.md) |
| `pay` | Send a classic payment with SEP-29 memo enforcement; supports staged build/sign/submit. | [stellar-ops](stellar-ops.md) |
| `claim` | Claim a claimable balance by ID behind claimant, predicate, and trustline pre-flight guards; supports staged build/sign/submit. | [stellar-ops](stellar-ops.md) |
| `balances` | Read native XLM and trustline balances for an account (read-only). | [stellar-ops](stellar-ops.md) |
| `trustline` | Create or remove a classic trustline (`ChangeTrust`) behind the ordered trust gate. | [stellar-ops](stellar-ops.md) |
| `friendbot` | Fund a testnet or futurenet account via the Friendbot endpoint (read-only; mainnet refused). | [stellar-ops](stellar-ops.md) |
| `fees` | Fetch Stellar RPC fee statistics for classic fee selection (read-only). | [stellar-ops](stellar-ops.md) |
| `counterparty` | Manage the cached `stellar.toml` bindings that back the counterparty allowlist policy. | [profile-and-governance](profile-and-governance.md) |
| `vault` | Deposit into or withdraw from a DeFindex vault via the smart-account (signing). | [defi-and-pool](defi-and-pool.md) |
| `trade` | Swap tokens via the Soroswap router-direct path via the smart-account (signing). | [defi-and-pool](defi-and-pool.md) |
| `pool` | Initialise and inspect a channel-account pool for parallel transaction submission. | [defi-and-pool](defi-and-pool.md) |
| `profile` | Create, list, show, migrate, and rotate the keyring-backed keys of a profile. | [profile-and-governance](profile-and-governance.md) |
| `credentials` | Register, list, show, and delete WebAuthn passkeys in the per-profile registry. | [profile-and-governance](profile-and-governance.md) |
| `approve` | Read a pending approval, prompt y/n, and record the HMAC attestation; garbage-collect expired approvals. | [profile-and-governance](profile-and-governance.md) |
| `audit` | Walk and verify the integrity of a hash-chained audit log, and repair its tip anchor. | [profile-and-governance](profile-and-governance.md) |
| `toolsets` | Install, list, run, and uninstall agent toolsets with cryptographic provenance verification. | [toolsets](../toolsets.md) |
| `mpp` | Authorize a sponsored testnet MPP charge, inspect durable state, record a host receipt, reconcile settlement, and prune old terminal replay markers. | [agent payments](../agent-payments.md) |

## Related pages

- [Smart-account commands](smart-account.md)
- [Core Stellar operations](stellar-ops.md)
- [DeFi and channel-account pool commands](defi-and-pool.md)
- [Profiles, credentials, approval, and audit](profile-and-governance.md)
- [Toolsets](../toolsets.md)
- [MPP agent payments](../agent-payments.md)
- [Concepts](../concepts.md)
