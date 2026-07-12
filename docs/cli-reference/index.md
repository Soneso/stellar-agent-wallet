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

- `cargo binstall stellar-agent-cli@0.1.0-alpha.4` — downloads the prebuilt GitHub release archive for your target, resolved via crates.io (`stellar-agent-<version>-<target>.tar.xz`, or `.zip` on Windows; the `stellar-agent` CLI and the `stellar-agent-mcp` server ship in one archive).
- `cargo install stellar-agent-cli@0.1.0-alpha.4` — builds from the published sources; the installed binary is named `stellar-agent`.
- Building from a clone with `cargo build --release`.

## Global conventions

There are no flags on the top-level command. Network selection, the profile, RPC URLs, and the signer source are declared per subcommand. The recurring flags below have the same meaning everywhere they appear; the per-group pages reference this section rather than restating them.

### Profile

`--profile <NAME>` selects the [profile](../concepts.md) — the per-environment TOML config that binds a CAIP-2 chain, an RPC endpoint, keyring entry references, thresholds, and the active policy engine. A profile holds no secrets; it only names keyring entries.

The effective profile name is resolved in this order:

1. An explicit `--profile <NAME>` flag.
2. The `STELLAR_AGENT_PROFILE` environment variable.
3. The literal `"default"`.

Some commands take the profile as a positional argument instead of a flag (the `profile` group itself); those cases are noted on their page.

### Network

`--network <NETWORK>` accepts `testnet` (the default) or `mainnet`, case-insensitive; no other value is accepted. The CAIP-2 chain id (`stellar:testnet` or `stellar:mainnet`) drives passphrase resolution and the mainnet-write gate. Not every command exposes `--network`: the read-only `balances` command selects its network through `--rpc-url` instead.

`testnet` is the default everywhere. `mainnet` is accepted for read-only commands, selected via `--network` where the command exposes it or via `--rpc-url` for `balances`. Every write or signing command structurally refuses `mainnet` in this alpha — see [Mainnet-write refusal](#mainnet-write-refusal).

A few commands derive their network from the loaded profile rather than from a `--network` flag (for example `trustline`, which takes `--chain-id <CAIP2>`). This is noted on the relevant page.

### RPC endpoints

- `--rpc-url <URL>` — the primary Soroban RPC endpoint. On most commands the default is `https://soroban-testnet.stellar.org`. URLs are validated against an allow-list on the commands that resolve them.
- `--secondary-rpc-url <URL>` — a second RPC endpoint for two-RPC cross-checks (for example, divergence detection on WASM-hash pins). Optional; its absence resolves per command:
  - On `lend`, `vault`, `trade`, and `smart-account rules` the dual-RPC cross-check is disabled and verification proceeds against the primary endpoint only.
  - On the `smart-account timelock` commands it falls back to the primary `--rpc-url` and warns that the divergence defence is then off.
  - `smart-account multicall` requires it (set on the flag or as `secondary_rpc_url` in the profile) and errors when it is absent.

### Timeout

`--timeout-seconds <SECONDS>` bounds submission and simulation. The default is `60`.

### Output format

`--output <FORMAT>` accepts `json` (the default) or `table`. The `table` form is offered on some commands and deferred on others; where deferred, `json` is emitted regardless. A few commands do not accept `--output` at all (noted on their pages).

### Signer source

Signing commands take a mutually exclusive signer-source group. Exactly one source is selected:

- The secret-env flag — the name of an environment variable holding the source account S-strkey. Set the variable to your secret; pass the variable name, never the secret itself. This flag is spelled `--secret-env` on `pay` and `accounts create`, `--deployer-secret-env` on `accounts deploy-c`, and `--signer-secret-env` on the `smart-account` commands; the per-group pages give the exact spelling.
- `--sign-with-ledger` — sign with a connected Ledger hardware device.
- `--account-index <INDEX>` — the BIP-44 account index for the Ledger derivation path. Default `0`.

```bash
export WALLET_SK="S..."   # your source-account secret key
stellar-agent pay GDEST...WXYZ "10 XLM" --source GSRC...WXYZ --secret-env WALLET_SK
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

This is a testnet-first alpha. `testnet` is the default network and Friendbot funding is testnet-only.

`mainnet` is accepted for read-only commands (for example reading a context rule or listing rules). Every write or signing command structurally refuses `mainnet` before any RPC call is made and before any signing key is touched. The refusal surfaces as the wire code `network.mainnet_write_forbidden` (the `friendbot` command uses `network.friendbot_mainnet_forbidden`). Because the check runs ahead of network and key access, a mistaken `--network mainnet` on a write command cannot reach the chain or unlock a seed.

## Startup advisory

Before dispatching any command, the CLI runs a local-only startup advisory: it scans the profile's audit log for context rules that reference revoked or retired verifier WASM hashes. The scan issues no network calls and is non-fatal. If it cannot run, the error is logged at warn level and the command proceeds. The advisory resolves its audit-log path from the first `--profile <NAME>` in the arguments, or `"default"` when absent.

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
| `lend` | Supply, borrow, repay, or withdraw against a Blend lending pool via the smart-account (signing). | [defi-and-pool](defi-and-pool.md) |
| `vault` | Deposit into or withdraw from a DeFindex vault via the smart-account (signing). | [defi-and-pool](defi-and-pool.md) |
| `trade` | Swap tokens via the Soroswap router-direct path via the smart-account (signing). | [defi-and-pool](defi-and-pool.md) |
| `pool` | Initialise and inspect a channel-account pool for parallel transaction submission. | [defi-and-pool](defi-and-pool.md) |
| `profile` | List, show, migrate, and rotate the keyring-backed keys of a profile. | [profile-and-governance](profile-and-governance.md) |
| `credentials` | Register, list, show, and delete WebAuthn passkeys in the per-profile registry. | [profile-and-governance](profile-and-governance.md) |
| `approve` | Read a pending approval, prompt y/n, and record the HMAC attestation; garbage-collect expired approvals. | [profile-and-governance](profile-and-governance.md) |
| `audit` | Walk and verify the integrity of a hash-chained audit log. | [profile-and-governance](profile-and-governance.md) |
| `toolsets` | Install, list, run, and uninstall agent toolsets with cryptographic provenance verification. | [toolsets](../toolsets.md) |

## Related pages

- [Smart-account commands](smart-account.md)
- [Core Stellar operations](stellar-ops.md)
- [DeFi and channel-account pool commands](defi-and-pool.md)
- [Profiles, credentials, approval, and audit](profile-and-governance.md)
- [Toolsets](../toolsets.md)
- [Concepts](../concepts.md)
