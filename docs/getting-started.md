# Getting started

The Stellar Agent Wallet is a Stellar wallet built for AI agents. It lets an
autonomous agent transact on Stellar under guardrails: a policy engine evaluates
each action, an operator-approval spine records out-of-band approvals, and a
tamper-evident hash-chained audit log records every invocation. It ships two
surfaces over the same core: the `stellar-agent` command-line binary and the
`stellar-agent-mcp` MCP stdio server.

This guide walks a first-time user through install, profile setup, funding a
testnet account, checking a balance, and making a first payment.

Throughout, replace placeholder identifiers (`GABC...WXYZ`, `WALLET_SK`) with
your own values. Never paste a real secret seed into a shell history; the wallet
reads secret keys from a named environment variable, not from the command line.

## Network and safety defaults

- `stellar:testnet` is the default network. Friendbot funding is testnet-only.
- `stellar:mainnet` is accepted for read-only commands — selected via
  `--network` where the command exposes it, or via `--rpc-url` for `balances`
  (which has no `--network` flag) — but every write or signing command
  structurally refuses mainnet (see [Mainnet is refused for
  writes](#mainnet-is-refused-for-writes)).
- CLI commands print a JSON envelope on stdout by default. Exit code is `0` on
  success and `1` on any error; the envelope's `error.code` carries the
  diagnostic.

## Prerequisites

- No prerequisites if you install a prebuilt binary.
- A Rust stable toolchain only if you build from source. The repository pins the
  channel via `rust-toolchain.toml` (`channel = "stable"`).
- Before running commands, note that some need only a classic keyring key while
  others require a deployed smart-account contract. See
  [the two account models](concepts.md#two-account-models) for the split and a
  prerequisite map.

## Install

### Prebuilt binaries (cargo binstall)

The declared install path is [`cargo binstall`](https://github.com/cargo-bins/cargo-binstall)
from GitHub release archives. A single release archive carries both binaries:

- Archive name: `stellar-agent-<version>-<target>.tar.xz` (`.zip` on Windows).
- Binaries inside: `stellar-agent` and `stellar-agent-mcp`.

```bash
cargo binstall --git https://github.com/Soneso/stellar-agent-wallet stellar-agent-cli
cargo binstall --git https://github.com/Soneso/stellar-agent-wallet stellar-agent-mcp
```

The release archives these commands fetch are published with each tagged
release on the repository's releases page. If none is listed yet, build from
source as shown below. crates.io publication is planned for a future release.

Every release ships supply-chain verification artifacts alongside the
archives: a `SHA256SUMS` file, a Sigstore bundle per archive, and in-toto
build provenance. Verify a download against those before running it.

#### macOS Gatekeeper note

The macOS binaries are currently ad-hoc signed, not Developer-ID signed or
notarized, so a downloaded binary is blocked on first run with "Apple cannot
check it for malicious software." After verifying the archive against
`SHA256SUMS` or its Sigstore bundle, approve the binary once with either:

```bash
xattr -d com.apple.quarantine ./stellar-agent ./stellar-agent-mcp
```

or right-click the binary in Finder and choose Open. Binaries built from
source or installed via `cargo install` carry no quarantine attribute and are
unaffected.

### Build from source

Building from source works today. Clone the repository and build with Cargo:

```bash
git clone https://github.com/Soneso/stellar-agent-wallet
cd stellar-agent-wallet
cargo build --release
```

The two binaries are produced at:

- `target/release/stellar-agent`
- `target/release/stellar-agent-mcp`

`cargo install --git https://github.com/Soneso/stellar-agent-wallet` also works
to place the binaries on your `PATH`; the `stellar-agent-cli` crate installs the
binary named `stellar-agent`.

When `stellar-agent` is on your `PATH`, the incumbent `stellar-cli` discovers it
as an external subcommand: `stellar agent ...` and `stellar-agent ...` invoke the
same binary.

Confirm the install:

```bash
stellar-agent --help
```

## Set up a profile

A profile is a per-environment TOML config (schema version 2) that binds a CAIP-2
chain id, an RPC endpoint, keyring entry references, thresholds, and the active
policy engine. A profile holds no secrets; it only names keyring entries. The
signer seed, nonce key, and all HMAC keys live in the platform keyring (macOS
Keychain, Linux Secret Service, Windows Credential Manager). The profile TOML is
safe to back up.

**Windows: Credential Manager requires an interactive logon session.** A
non-interactive process — a Windows service, an SSH session, or a scheduled
task — cannot access Credential Manager and every keyring operation fails with
`auth.keyring_interactive_session_required`. Run the wallet from an interactive
desktop session (Remote Desktop counts), deploy it inside a container / Linux
VM where the platform keyring backend does not have this restriction, or opt
into the headless keyring store described below.

**Headless deployments (Windows service/SSH/CI, Linux services): the opt-in
file-backed keyring store.** Set `STELLAR_AGENT_KEYRING_BACKEND=headless-dpapi`
(Windows, DPAPI CurrentUser scope) or `STELLAR_AGENT_KEYRING_BACKEND=headless-env`
(any platform; also requires `STELLAR_AGENT_HEADLESS_KEYRING_KEY`, a 32-byte
URL-safe-base64 key) on the process environment before running any
`stellar-agent` or `stellar-agent-mcp` command. The platform keyring remains
the default when this variable is unset. See [security-internals.md's headless
keyring section](maintainers/security-internals.md#headless-keyring-store)
for the trust model and protection-mode details before enabling it.

Profiles live in the OS-conventional directory, one TOML file per profile name:

| Platform | Path |
|----------|------|
| Linux    | `~/.local/share/stellar-agent/profiles/<name>.toml` |
| macOS    | `~/Library/Application Support/Soneso.stellar-agent/profiles/<name>.toml` |
| Windows  | `%LOCALAPPDATA%\Soneso\stellar-agent\data\profiles\<name>.toml` |

The default profile name is `default`. The `balances` and `pay` commands below
take an explicit `--account`/`--source` and `--rpc-url` (defaulting to the
testnet RPC), so they work without authoring a profile file. Profile-aware
commands synthesise an in-memory testnet profile when no `default.toml` exists.
To make a profile persistent, place a TOML file at the path above. A minimal
version-2 testnet profile:

```toml
version = 2
chain_id = "stellar:testnet"
rpc_url = "https://soroban-testnet.stellar.org"

[mcp_signer_default]
service = "stellar-agent-signer-default"
account = "GABC...WXYZ"

[mcp_nonce_key_alias]
service = "stellar-agent-nonce-default"
account = "default"

[audit_log_hash_chain_key_id]
service = "stellar-agent-audit-default"
account = "default"

[policy_owner_key_id]
service = "stellar-agent-owner-default"
account = "default"

[attestation_key_id]
service = "stellar-agent-attestation-default"
account = "default"

[counterparty_cache_key_id]
service = "stellar-agent-counterparty-default"
account = "default"

[policy]
engine = "noop"
```

In `[mcp_signer_default]`, `account` is the signer's identity: it must be the
G-strkey (public address) that the enrolled signer seed derives to. The MCP tools
and the keyring-signing CLI verbs verify the loaded seed against this value, so a
placeholder such as `"default"` never signs. Replace `GABC...WXYZ` with your
signer's public address and enroll the matching seed with
[`profile enroll-signer`](#enroll-the-mcp-signer). The `account` field on the
other entries is only a keyring coordinate label and may stay `"default"`.

The `[policy] engine` value is `noop` or `v1`:

- `noop` — the Noop engine: testnet allow-all; on mainnet it allows read-only
  commands and refuses destructive ones with `policy.engine_required`.
- `v1` — the V1 engine: a signature-verified, typed-criteria, first-match
  default-deny engine. The V1 engine requires the owner public key enrolled
  (`profile enroll-owner-key`) plus the attestation and audit keyring keys
  (`profile rotate-attestation-key`, `profile rotate-audit-key`), and a policy
  file signed with `profile sign-policy`; enable it only after that setup.

A version-2 profile must declare a `[policy]` block explicitly; there is no
silent default, and a v2 file without one is refused at load. The example above
chooses `noop` for a permissive testnet start. When the wallet mints a profile
for you it writes `engine = "v1"`, and a profile migrated from an older schema
is set to `noop`.

The CLI reads and manages existing profiles:

```bash
# List known profile names.
stellar-agent profile list

# Print a profile's resolved configuration (no secrets are printed).
stellar-agent profile show default

# Migrate an older profile file to the current schema version.
stellar-agent profile migrate default
```

For the full profile schema, every field, and the key-rotation ceremony, see
[Profiles](profiles.md).

## Create and fund a testnet account

If you do not already hold an account, generate one and fund it in a single
step. `--generate` mints a fresh ed25519 keypair in-process and returns both the
G-strkey and the secret in the JSON envelope (the secret in `data.secret_key`,
never in `--output table` and never logged); `--fund-with-friendbot` funds it
from Friendbot (testnet only). Capture the printed keys and export the secret so
the signing commands below can read it:

```bash
stellar-agent accounts create --generate --fund-with-friendbot
export WALLET_SK=S...printed-secret...
```

To fund an account you already hold, call Friendbot directly. Mainnet is
structurally refused (`network.friendbot_mainnet_forbidden`) before any HTTP
call.

```bash
stellar-agent friendbot --account GABC...WXYZ --network testnet
```

Flags:

- `--account <G_STRKEY>` — the account to fund (required).
- `--network <NETWORK>` — `testnet` (default) or `futurenet`; `mainnet` is
  rejected at dispatch.
- `--friendbot-url <URL>` — override the Friendbot endpoint; the URL is validated
  against an allow-list unless `--friendbot-url-unchecked` is set.
- `--output <FORMAT>` — `json` (default) or `table`.

## Enroll the MCP signer

The MCP fund-movement tools and the keyring-signing CLI verbs (`trustline`,
`lend`, `trade`, `vault`) resolve their signer from the profile's
`mcp_signer_default` keyring entry. On a fresh install that entry is empty, so
those paths fail with `auth.keyring_not_found` until you enroll a seed. Enrollment
reads the `S...` secret from a named environment variable, derives its public
address, and stores it in the platform keyring — the secret is never printed.

Set `[mcp_signer_default] account` in the profile to the signer's public address
first (enrollment refuses if it does not match the seed), then enroll:

```bash
export WALLET_SK=S...your-testnet-secret...
stellar-agent profile enroll-signer --profile default --secret-env WALLET_SK
```

Flags:

- `--secret-env <VAR>` — name of the environment variable holding the signer's
  S-strkey. The flag takes the variable name, never the secret.
- `--profile <NAME>` — profile whose `mcp_signer_default` entry is written
  (default `default`).
- `--expected-address <G_STRKEY>` — optional guard; enrollment refuses unless the
  seed derives to this address.
- `--force` — replace an already-enrolled entry.

The JSON envelope reports the derived `public_address` and the keyring coordinate
written. If the profile's `account` does not match the derived address, the
command refuses and prints the address to set `account` to.

## Check a balance

`balances` shows the native XLM balance and trustlines for an account. It is
read-only; it makes no key access and does not sign. It queries the Stellar RPC
endpoint (not Horizon).

```bash
stellar-agent balances --account GABC...WXYZ
```

Flags:

- `--account <G_STRKEY>` — the account to query (required).
- `--rpc-url <URL>` — Stellar RPC endpoint; defaults to
  `https://soroban-testnet.stellar.org`.
- `--asset <CODE:ISSUER>` — a trustline asset to query alongside native XLM;
  repeat to query several. Assets the account does not trust are omitted.
- `--output <FORMAT>` — `json` (default) or `table`.

```bash
stellar-agent balances \
  --account GABC...WXYZ \
  --asset USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN
```

## Make a first payment on testnet

`pay` sends a payment. By default it builds, signs, and submits the transaction
atomically, then polls until confirmation. It enforces SEP-29 memo-required
destinations before signing.

Provide the secret key through an environment variable named with `--secret-env`;
the wallet reads the variable, never the literal key on the command line. Amounts
carry explicit units.

```bash
export WALLET_SK=S...your-testnet-secret...
stellar-agent pay GDEST...WXYZ "10 XLM" \
  --source GABC...WXYZ \
  --secret-env WALLET_SK \
  --memo-text "invoice-42"
```

Signer source (one of the following, mutually exclusive):

- `--secret-env <VAR>` — name of the environment variable holding the source
  account's S-strkey.
- `--sign-with-ledger` — sign with a connected Ledger; the seed never enters
  process memory. Pair with `--account-index <INDEX>` (default `0`).

Other common flags:

- `<DESTINATION>` (positional) — destination account G-strkey (required).
- `<AMOUNT>` (positional) — amount with units, e.g. `"10 XLM"`, `"10.5 USDC"`.
- `[ASSET]` (positional) — `native`, `XLM`, or `CODE:ISSUER_GSTRKEY`; defaults to
  `native`.
- `--source <G_STRKEY>` — source account; required for signing.
- `--memo-text <STRING>` / `--memo-id <U64>` / `--memo-hash <64_HEX>` /
  `--memo-return <64_HEX>` — mutually exclusive memo options.
- `--fee <STROOPS|auto[:pNN]>` — classic fee per operation.
- `--timeout-seconds <SECONDS>` — submission/confirmation polling timeout;
  defaults to `60`.
- `--rpc-url <URL>` — RPC endpoint override; defaults to the testnet RPC.
- `--output <FORMAT>` — `json` (default) or `table`.

### The unlock window

For the `--secret-env` path, the 32-byte signing seed is loaded into the unlock
window: a short TTL-bounded period during which the seed is resident in pinned,
zeroize-on-drop memory (mlock). The TTL is the profile's `[wallet]
unlock_ttl_seconds` (default 30 seconds); it must be in the range 1 to 600
seconds, and a value of 0 or above 600 is refused when the window is constructed
— never clamped. The profile's `[wallet] mlock_required` governs what happens
if the seed cannot be pinned in RAM: `true` (the default on Linux/macOS) fails
the signing call closed. The window is active only for the duration of a single
signing call; the seed is zeroized and the lock released on every exit path. The
`--sign-with-ledger` path holds no seed in memory.

### Staged pipeline

You can run the stages independently. The flags are mutually exclusive:

- `--build-only` — emit the unsigned envelope XDR and exit (no signing).
- `--sign-only <BASE64_XDR>` — sign a previously built envelope and emit signed
  XDR.
- `--submit-only <BASE64_XDR>` — submit a signed envelope.

`--use-oz-relayer` is an opt-in that is not implemented in this build: it prints
an AGPL-3.0 disclosure to stderr and declines with
`validation.relayer_not_implemented`. See the [CLI reference](cli-reference/index.md)
for the full flag set.

### Mainnet is refused for writes

Targeting mainnet on a write command is refused before any RPC call or signing:

```bash
stellar-agent pay GDEST...WXYZ "10 XLM" \
  --source GABC...WXYZ --secret-env WALLET_SK --network mainnet
# exit code 1; error.code = network.mainnet_write_forbidden
```

## Next steps

- [Concepts](concepts.md) — the profile, unlock window, policy engine and
  criteria, approval spine and attestation, audit log, and smart-account context
  rules.
- [CLI reference](cli-reference/index.md) — every subcommand, flag, and default.
- [MCP server](mcp.md) — running `stellar-agent-mcp` as an MCP stdio server.
- [Profiles](profiles.md) — the full profile schema and the key-rotation
  ceremony.
