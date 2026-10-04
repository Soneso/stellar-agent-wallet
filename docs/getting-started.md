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
[Pass a secret seed](#pass-a-secret-seed) shows how to set that variable.

## Network and safety defaults

- `stellar:testnet` is the default network. Friendbot funding is testnet-only.
- `stellar:mainnet` is accepted for read-only commands. Select it with a
  mainnet profile (`--profile <NAME>`), or with `--rpc-url` for `balances`
  (which has no `--network` flag). `--network` asserts the profile's chain
  and never selects one. On a mainnet profile, every command that signs a
  ledger transaction refuses before any RPC call or signer access (see
  [Mainnet is refused for writes](#mainnet-is-refused-for-writes)). `tx` signs
  nothing, and `pool init` is the only `pool` command that signs.
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
cargo binstall --locked --disable-strategies quick-install,compile stellar-agent-cli@0.1.0-alpha.9 stellar-agent-mcp@0.1.0-alpha.9
```

While only prerelease (alpha) versions are published on crates.io, the version
must be spelled out. A bare crate name matches stable versions only. The
release archives this command fetches are published with each tagged release
on the repository's releases page.

Release archives exist for five targets: `x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, and
`x86_64-pc-windows-msvc`. `cargo binstall` installs the archive for the host's
target, or for a compatible target the host runs, such as the x86_64 Windows
archive under emulation. With `--disable-strategies quick-install,compile`, it
fails when no such archive exists; on other hosts, use
[`cargo install --locked`](#cargo-install-from-cratesio) or
[build from source](#build-from-source). `cargo binstall` checks the download
over TLS only, with no signature. `--locked` applies when binstall builds from
source, which the strategy flag turns off. The strategy flag needs
cargo-binstall 0.17.0 or later.

Without any Rust tooling, fetch and extract the archive directly (substitute
your target):

```bash
curl -fsSLO https://github.com/Soneso/stellar-agent-wallet/releases/download/v0.1.0-alpha.9/stellar-agent-0.1.0-alpha.9-aarch64-apple-darwin.tar.xz
tar -xJf stellar-agent-0.1.0-alpha.9-aarch64-apple-darwin.tar.xz
```

Every release ships supply-chain verification artifacts alongside the
archives: a `SHA256SUMS` file, a Sigstore bundle per archive, and in-toto
build provenance. Verify a download against those before running it.

#### macOS Gatekeeper note

The release signs the macOS binaries with a Developer ID and notarizes them. A
bare executable carries no stapled ticket, so Gatekeeper checks notarization
online. To check a binary yourself:

```bash
codesign -dvv ./stellar-agent
spctl -a -vv -t install ./stellar-agent
```

`codesign` prints `Authority=Developer ID Application` with the signing team,
and `spctl` prints `accepted` and `source=Notarized Developer ID`. Run both
commands on `./stellar-agent-mcp` too.

### cargo install (from crates.io)

Builds the binaries from the sources published on crates.io and places them on
your `PATH`; the `stellar-agent-cli` crate installs the binary named
`stellar-agent`:

```bash
cargo install --locked stellar-agent-cli@0.1.0-alpha.9 stellar-agent-mcp@0.1.0-alpha.9
```

`--locked` makes cargo build with the `Cargo.lock` published in the crate.

### Build from source

Clone the release tag and build with its committed `Cargo.lock`:

```bash
git clone --branch v0.1.0-alpha.9 https://github.com/Soneso/stellar-agent-wallet
cd stellar-agent-wallet
cargo build --release --locked
```

The two binaries are produced at:

- `target/release/stellar-agent`
- `target/release/stellar-agent-mcp`

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
non-interactive process, such as a Windows service, an SSH session, or a scheduled
task, cannot access Credential Manager and every keyring operation fails with
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

The default profile name is `default`. The `balances` command takes an
explicit `--account` and `--rpc-url` (defaulting to the testnet RPC), and
`pay` reads its endpoint from the profile, so both work without authoring a
profile file. Profile-aware commands synthesise an in-memory testnet profile
when no profile was *named* and no `default.toml` exists. A profile you name (with `--profile` or `STELLAR_AGENT_PROFILE`) is never replaced by that fallback.
If its file does not exist, the command refuses.

To create a persistent profile, run `profile init`:

```bash
stellar-agent profile init
```

This writes `<profile_dir>/default.toml` with `engine = "v1"` (the default)
and placeholder signer/nonce keyring coordinates. The full setup flow is:

1. `profile init`: create the profile file (this step).
2. [`profile enroll-signer`](#enroll-the-mcp-signer): register the MCP signer seed.
3. `profile rotate-audit-key`: mint the audit chain-root key. Required on
   **every** engine, `noop` included: `init` mints the audit-log keyring
   coordinate only, no key material, so every signing verb refuses
   `audit.chain_key_unavailable` until this runs.
4. For the `v1` engine only, the rest of the ceremony: `profile
   enroll-owner-key`, `profile rotate-attestation-key`, then `profile
   sign-policy` (the normative list is the
   [`profile init` reference entry](cli-reference/profile-and-governance.md#profile-init);
   see also [Opt in to V1](profiles.md#opt-in-to-v1)).

Pass `--profile <NAME>` for a non-default profile, `--rpc-url <URL>` to
override the testnet default. Pass `--network mainnet --rpc-url <URL>` for a
mainnet profile. Mainnet has no default endpoint, so it requires an explicit
`https://` `--rpc-url` with no username or password. Pass `--engine noop` to
skip the V1 owner-key ceremony for now. See [`profile
init`](cli-reference/profile-and-governance.md#profile-init) for the full
flag reference.

Every profile-aware command takes the same `--profile <NAME>`, and so does the
MCP server (`stellar-agent-mcp --profile <NAME>`); `STELLAR_AGENT_PROFILE` in
the environment sets the name for both when the flag is absent. A profile file
belongs to its name: back it up freely, but restoring it under a different file
name does not create a second profile. Run `profile init` for that.

A `v1` profile does not serve MCP requests until the ceremony below is complete;
the server refuses to start and names the step that is missing. `--engine noop`
is the way to have a working server immediately.

For reference, here is the shape a testnet profile takes after enrolling a
signer (a minimal version-2 profile). It is shown here with `engine = "noop"` for a
permissive testnet start. `profile init`'s default is `engine = "v1"`:

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
placeholder such as `"default"` never signs. A profile minted by `profile init`
starts with that placeholder; running
[`profile enroll-signer`](#enroll-the-mcp-signer) populates it automatically
with the enrolled seed's derived address. To pin the signer identity to a
specific address in advance, refusing any other seed, set `account` to that
G-strkey yourself before enrolling. The `account` field on the other entries is
only a keyring coordinate label and may stay `"default"`.

The `[policy] engine` value is `noop` or `v1`. Both engines require
`profile rotate-audit-key` before any signing verb will proceed. That
requirement is independent of the policy engine.

- `noop`: the Noop engine: testnet allow-all; on mainnet it allows read-only
  commands and refuses destructive ones with `policy.engine_required`.
- `v1`: the V1 engine: a signature-verified, typed-criteria, first-match
  default-deny engine. On top of the audit key above, the V1 engine requires
  the owner public key enrolled (`profile enroll-owner-key`) plus the
  attestation keyring key (`profile rotate-attestation-key`), and a policy
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

## Pass a secret seed

Signing commands read a secret seed from the environment variable that
`--secret-env` names. Read the seed without echo, export it only for the
commands that need it, and unset it afterwards. A seed typed into a command line
lands in the shell history file.

In bash or zsh, run this line on its own, paste the seed when prompted, and
press Enter. It prints nothing while you paste:

```bash
printf 'WALLET_SK seed: ' && read -rs WALLET_SK && echo && export WALLET_SK
```

Run the commands that use the seed, then remove it from the shell:

```bash
unset WALLET_SK
```

Every program the shell starts while the variable is set inherits it, so unset
it before you start anything else from that shell, such as an MCP client.

In PowerShell 7.1 and later:

```powershell
$env:WALLET_SK = Read-Host -MaskInput 'WALLET_SK seed'
```

In Windows PowerShell 5.1 and later:

```powershell
$env:WALLET_SK = [System.Net.NetworkCredential]::new('', (Read-Host -AsSecureString 'WALLET_SK seed')).Password
```

In both, remove the seed when you are done:

```powershell
Remove-Item Env:WALLET_SK
```

`cmd.exe` has no input that hides typing, so use PowerShell on Windows.

### Remove a seed from shell history

A seed typed into a command line earlier, for example in an `export` line, is
in the shell history. To remove it:

1. Close every shell that typed the seed, or clear its in-memory history first.
   An open shell writes its history to the file when it exits.
2. Delete the lines that hold the seed from `~/.bash_history` and
   `~/.zsh_history`. On macOS, also delete them from the files in
   `~/.zsh_sessions/` and `~/.bash_sessions/` whose names end in `.history`
   or `.historynew`.
3. If the account holds value, move it to a new key and enroll that key.

## Create and fund a testnet account

If you do not already hold an account, generate one and fund it in a single
step. `--generate` mints a fresh ed25519 keypair in-process and returns both the
G-strkey and the secret in the JSON envelope (the secret in `data.secret_key`,
never in `--output table` and never logged). `--fund-with-friendbot` funds it
from Friendbot (testnet only):

```bash
stellar-agent accounts create --generate --fund-with-friendbot
```

Save the printed secret; the [enroll](#enroll-the-mcp-signer) and
[payment](#make-a-first-payment-on-testnet) steps read it. The command output
holds the seed, so do not write it to a log or a shared terminal.

To fund an account you already hold, call Friendbot directly. Mainnet is
structurally refused (`network.friendbot_mainnet_forbidden`) before any HTTP
call.

```bash
stellar-agent friendbot --account GABC...WXYZ --network testnet
```

Flags:

- `--account <G_STRKEY>`: the account to fund (required).
- `--network <NETWORK>`: `testnet` (default) or `futurenet`; `mainnet` is
  rejected at dispatch.
- `--friendbot-url <URL>`: override the Friendbot endpoint; the URL is validated
  against an allow-list unless `--friendbot-url-unchecked` is set.
- `--output <FORMAT>`: `json` (default) or `table`.

## Enroll the MCP signer

The MCP fund-movement tools and the keyring-signing CLI verbs (`trustline`,
`trade`, `vault`) resolve their signer from the profile's
`mcp_signer_default` keyring entry. On a fresh install that entry is empty, so
those paths fail with `auth.keyring_not_found` until you enroll a seed. Enrollment
reads the `S...` secret from a named environment variable, derives its public
address, and stores it in the platform keyring. The secret is never printed.
These same three verbs also require the profile's audit chain-root key to be
minted (`profile rotate-audit-key <name>`, step 3 above); before that they
refuse `audit.chain_key_unavailable`.

On a profile fresh from `profile init`, `mcp_signer_default.account` is still
the placeholder `"default"`; enrollment populates it automatically with the
enrolled seed's derived address. Run this line on its own, paste the seed when
prompted, and press Enter:

```bash
printf 'WALLET_SK seed: ' && read -rs WALLET_SK && echo && export WALLET_SK
```

Enroll the seed, then remove it from the shell:

```bash
stellar-agent profile enroll-signer --profile default --secret-env WALLET_SK
unset WALLET_SK
```

To pin the signer identity to a specific address in advance, refusing any
other seed, set `account` to that G-strkey yourself before enrolling;
enrollment then refuses on a mismatch rather than overwriting it.

Flags:

- `--secret-env <VAR>`: name of the environment variable holding the signer's
  S-strkey. The flag takes the variable name, never the secret.
- `--profile <NAME>`: profile whose `mcp_signer_default` entry is written
  (default `default`).
- `--expected-address <G_STRKEY>`: optional guard; enrollment refuses unless the
  seed derives to this address.
- `--force`: replace an already-enrolled entry.

The JSON envelope reports the derived `public_address`, the keyring coordinate
written, and `account_populated` (`true` when a placeholder was filled in,
`false` when the account already pinned an identity). If the profile's
`account` already pins a *different* G-strkey than the derived address, the
command refuses and prints the address to set `account` to.

## Check a balance

`balances` shows the native XLM balance and trustlines for an account. It is
read-only; it makes no key access and does not sign. It queries the Stellar RPC
endpoint (not Horizon).

```bash
stellar-agent balances --account GABC...WXYZ
```

`balances` keeps its testnet endpoint default. Transaction commands instead read endpoints from their resolved profile.

Flags:

- `--account <G_STRKEY>`: the account to query (required).
- `--rpc-url <URL>`: Stellar RPC endpoint; defaults to
  `https://soroban-testnet.stellar.org`.
- `--asset <CODE:ISSUER>`: a trustline asset to query alongside native XLM;
  repeat to query several. Assets the account does not trust are omitted.
- `--output <FORMAT>`: `json` (default) or `table`.

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
carry explicit units. Run this line on its own, paste the seed when prompted,
and press Enter:

```bash
printf 'WALLET_SK seed: ' && read -rs WALLET_SK && echo && export WALLET_SK
```

Send the payment, then remove the seed from the shell:

```bash
stellar-agent pay GDEST...WXYZ "10 XLM" \
  --source GABC...WXYZ \
  --secret-env WALLET_SK \
  --memo-text "invoice-42"
unset WALLET_SK
```

Signer source (one of the following, mutually exclusive):

- `--secret-env <VAR>`: name of the environment variable holding the source
  account's S-strkey.
- `--sign-with-ledger`: sign with a connected Ledger; the seed never enters
  process memory. Pair with `--account-index <INDEX>` (default `0`).

Other common flags:

- `<DESTINATION>` (positional), destination account G-strkey (required).
- `<AMOUNT>` (positional), amount with units, e.g. `"10 XLM"`, `"10.5 USDC"`.
- `[ASSET]` (positional), `native`, `XLM`, or `CODE:ISSUER_GSTRKEY`; defaults to
  `native`.
- `--source <G_STRKEY>`: source account; required for signing.
- `--memo-text <STRING>` / `--memo-id <U64>` / `--memo-hash <64_HEX>` /
  `--memo-return <64_HEX>`: mutually exclusive memo options.
- `--fee <STROOPS|auto[:pNN]>`: classic fee per operation.
- `--timeout-seconds <SECONDS>`: submission/confirmation polling timeout;
  defaults to `60`.
- `--rpc-url <URL>`: overrides a testnet profile's endpoint; refused on a
  mainnet profile. The endpoint comes from the profile when absent.
- `--output <FORMAT>`: `json` (default) or `table`.

### The unlock window

For the `--secret-env` path, the 32-byte signing seed is loaded into the unlock
window: a short TTL-bounded period during which the seed is resident in pinned,
zeroize-on-drop memory (mlock). The TTL is the profile's `[wallet]
unlock_ttl_seconds` (default 30 seconds). It must be in the range 1 to 600
seconds, and a value of 0 or above 600 is refused when the window is constructed
and never clamped. The profile's `[wallet] mlock_required` governs what happens
if the seed cannot be pinned in RAM: `true` (the default on Linux/macOS) fails
the signing call closed. The window is active only for the duration of a single
signing call; the seed is zeroized and the lock released on every exit path. The
`--sign-with-ledger` path holds no seed in memory.

### Staged pipeline

You can run the stages independently. The flags are mutually exclusive:

- `--build-only`: emit the unsigned envelope XDR and exit (no signing).
- `--sign-only <BASE64_XDR>`: sign a built envelope and emit signed
  XDR.
- `--submit-only <BASE64_XDR>`: submit a signed envelope.

`--use-oz-relayer` is an opt-in that is not implemented in this build: it prints
an AGPL-3.0 disclosure to stderr and declines with
`validation.relayer_not_implemented`. See the [CLI reference](cli-reference/index.md)
for the full flag set.

### Mainnet is refused for writes

On a mainnet profile, `pay` and the other guarded transaction and
smart-account write commands refuse before any RPC call or signer access.
[Mainnet-write refusal](cli-reference/index.md#mainnet-write-refusal) lists
them.

```bash
stellar-agent pay GDEST...WXYZ "10 XLM" \
  --source GABC...WXYZ --secret-env WALLET_SK --profile mainnet
# exit code 1; error.code = network.mainnet_write_forbidden
```

`--network mainnet` on a testnet profile refuses with
`profile.network_flag_mismatch`, because the flag asserts the profile's chain.
`trustline`, `trade`, `vault deposit`, `vault withdraw`, and `pool init` refuse
a mainnet profile the same way, before any RPC call or signer access. `tx`
signs nothing, and `pool init` is the only `pool` command that signs. The
submit layer refuses mainnet too. A mainnet network passphrase and a known
mainnet RPC URL each cost zero RPC calls; beyond those two the wallet asks the
endpoint which network it serves and refuses when the answer is mainnet. That
same answer, not the network you declared, is what the wallet checks the
envelope's signatures against, so an envelope signed for one network cannot be
submitted under another network's passphrase.

## Next steps

- [Concepts](concepts.md): the profile, unlock window, policy engine and
  criteria, approval spine and attestation, audit log, and smart-account context
  rules.
- [CLI reference](cli-reference/index.md): every subcommand, flag, and default.
- [MCP server](mcp.md): running `stellar-agent-mcp` as an MCP stdio server.
- [Profiles](profiles.md): the full profile schema and the key-rotation
  ceremony.
