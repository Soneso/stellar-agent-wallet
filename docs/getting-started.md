# Getting started

The Stellar Agent Wallet is a Stellar wallet built for AI agents. A policy
engine evaluates actions, and an operator-approval spine records out-of-band
approvals. A tamper-evident hash-chained audit log records transaction
submissions, signed authorizations, approvals, and explicit key-management and
lifecycle events. MCP balance reads and payment simulations produce no automatic
invocation row. Under V1, payment simulations can reconcile overdue reservations
and write settlement audit rows.
It ships two
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
  and never selects one.
  See [Mainnet configurations and scope](#mainnet-configurations-and-scope)
  for signing and write admission. `tx` signs nothing.
  `pool init` is the only `pool` command that signs.
- CLI commands print a JSON envelope on stdout by default. Exit code is `0` on
  success and `1` on any error; the envelope's `error.code` carries the
  diagnostic.

## Prerequisites

- A prebuilt binary needs no prerequisites.
- `cargo install` and a build from source need a stable Rust toolchain with
  edition 2024 support. The repository pins the channel in
  `rust-toolchain.toml` (`channel = "stable"`).
- A source build also compiles OpenSSL from vendored source, which needs a C
  compiler and Perl. On Windows this is a native Perl such as Strawberry Perl.
  The MSYS Perl that Git for Windows installs lacks required modules.
- On Linux, a source build also needs `libudev-dev` and `pkg-config` for the
  hardware-wallet USB transport.
- Some commands need only a classic keyring key, and others require a deployed
  smart-account contract. See
  [the two account models](concepts.md#two-account-models) for the split and a
  prerequisite map.

## Install

### Prebuilt binaries (cargo binstall)

The declared install path is [`cargo binstall`](https://github.com/cargo-bins/cargo-binstall)
from GitHub release archives. `cargo binstall` resolves the crate on crates.io
and downloads the prebuilt archive from the tagged release assets. A single
release archive carries both binaries:

- Archive name: `stellar-agent-<version>-<target>.tar.xz` (`.zip` on Windows).
- Top-level folder on every platform: `stellar-agent-<version>-<target>/`.
- Binaries inside that folder: `stellar-agent` and `stellar-agent-mcp` (`.exe` on Windows).

```bash
cargo binstall --locked --disable-strategies quick-install,compile stellar-agent-cli@0.1.0-alpha.12 stellar-agent-mcp@0.1.0-alpha.12
```

While crates.io holds only prerelease (alpha) versions, spell out the version.
A bare crate name matches stable versions only. Each tagged release publishes
the archives this command fetches on the repository's
[releases page](https://github.com/Soneso/stellar-agent-wallet/releases).

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

#### Download an archive directly

You can download and extract the archive without any Rust tooling. Substitute
your target in the commands.

Linux or macOS (this example selects Apple Silicon):

```bash
curl -fsSLO https://github.com/Soneso/stellar-agent-wallet/releases/download/v0.1.0-alpha.12/stellar-agent-0.1.0-alpha.12-aarch64-apple-darwin.tar.xz
curl -fsSLO https://github.com/Soneso/stellar-agent-wallet/releases/download/v0.1.0-alpha.12/SHA256SUMS
```

On Linux, check the checksum with `sha256sum --ignore-missing --check SHA256SUMS`.
On macOS, use `shasum -a 256 --ignore-missing --check SHA256SUMS`.
When the checksum matches, extract the archive. Then add its folder to this
shell's `PATH`:

```bash
tar -xJf stellar-agent-0.1.0-alpha.12-aarch64-apple-darwin.tar.xz
export PATH="$PWD/stellar-agent-0.1.0-alpha.12-aarch64-apple-darwin:$PATH"
```

Windows PowerShell:

```powershell
$release = 'https://github.com/Soneso/stellar-agent-wallet/releases/download/v0.1.0-alpha.12'
$folder = 'stellar-agent-0.1.0-alpha.12-x86_64-pc-windows-msvc'
$archive = "$folder.zip"
curl.exe -fsSLO "$release/$archive"
curl.exe -fsSLO "$release/SHA256SUMS"
$line = Get-Content SHA256SUMS | Where-Object { ($_ -split '\s+')[1] -eq $archive }
if (@($line).Count -ne 1) { throw 'Expected one archive entry in SHA256SUMS' }
$expected = ($line -split '\s+')[0]
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash
if ($actual -ne $expected) { throw 'Archive checksum mismatch' }
Expand-Archive -LiteralPath $archive -DestinationPath .
$env:PATH = "$((Resolve-Path -LiteralPath $folder).Path);$env:PATH"
```

Use `curl.exe`: Windows PowerShell's `curl` alias runs `Invoke-WebRequest`.
The `PATH` commands apply to the current shell. For future sessions, add the
folder to your shell configuration or Windows user `Path` environment variable.

Every release also ships a `SHA256SUMS` file, a Sigstore bundle per archive,
and in-toto build provenance. Check a download against them before you run it,
as [Verifying releases](verifying-releases.md) shows.

#### macOS Gatekeeper note

The release signs the macOS binaries with a Developer ID and notarizes them. A
bare executable carries no stapled ticket, so Gatekeeper checks notarization
online. From the extracted versioned folder, check a binary yourself:

```bash
codesign -dvv ./stellar-agent
spctl -a -vv -t install ./stellar-agent
```

`codesign` prints `Authority=Developer ID Application` with the signing team,
and `spctl` prints `accepted` and `source=Notarized Developer ID`. Run both
commands on `./stellar-agent-mcp` too.

When `spctl` answers `internal error in Code Signing subsystem`, that Mac's
assessment service could not complete the check, and the message says nothing
about the binary. The checksum step and the `codesign` output still verify the
download, and you can repeat the `spctl` check on another Mac.

### cargo install (from crates.io)

Builds the binaries from the sources published on crates.io and places them on
your `PATH`; the `stellar-agent-cli` crate installs the binary named
`stellar-agent`:

```bash
cargo install --locked stellar-agent-cli@0.1.0-alpha.12 stellar-agent-mcp@0.1.0-alpha.12
```

`--locked` makes cargo build with the `Cargo.lock` published in the crate.

### Build from source

Clone the release tag and build with its committed `Cargo.lock`:

```bash
git clone --branch v0.1.0-alpha.12 https://github.com/Soneso/stellar-agent-wallet
cd stellar-agent-wallet
cargo build --release --locked
```

The build writes the two binaries to:

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
policy engine. A profile names keyring entries instead of holding keys. The
signer seed, nonce key, and all HMAC keys live in the platform keyring (macOS
Keychain, Linux Secret Service, Windows Credential Manager). An endpoint URL can
embed a credential in its path or query on any network. Mainnet refuses only a
username or password in the URL. The profile TOML is safe to back up only when no
endpoint URL embeds a credential.

**Windows: Credential Manager requires an interactive logon session.** A
non-interactive process, such as a Windows service, an SSH session, or a scheduled
task, cannot access Credential Manager and every keyring operation fails with
`auth.keyring_interactive_session_required`. Run the wallet from an interactive
desktop session, where Remote Desktop counts. Alternatively, deploy it inside a
container / Linux VM where the platform keyring backend does not have this
restriction, or opt into the file-backed headless keyring store.

**Headless deployments (Windows service/SSH/CI, Linux services): the opt-in
file-backed keyring store.** Set `STELLAR_AGENT_KEYRING_BACKEND=headless-dpapi`
for Windows DPAPI CurrentUser protection, or `STELLAR_AGENT_KEYRING_BACKEND=headless-env`
on any platform. The `headless-dpapi` backend depends on access to the current
user's DPAPI master key and can fail in key-authenticated SSH sessions.
An interactive desktop logon may help. Such a failure reports
`auth.keyring_platform_error` naming DPAPI and the numeric `CryptProtectData`
error code when available. The `headless-env` backend has no such dependency and requires
`STELLAR_AGENT_HEADLESS_KEYRING_KEY`, a 32-byte URL-safe-base64 key without padding.
The wallet refuses a padded or standard-alphabet key with
`auth.keyring_config_invalid`, and the message names the cause.
Set these variables in the process environment before running any
`stellar-agent` or `stellar-agent-mcp` command. The platform keyring remains
the default when this variable is unset. See [security-internals.md's headless
keyring section](maintainers/security-internals.md#headless-keyring-store)
for the trust model and protection-mode details before enabling it.

The headless backends serve testnet. Mainnet needs the platform keyring:
mainnet readiness and `profile enable-mainnet` refuse a process with
`STELLAR_AGENT_KEYRING_BACKEND` set, with
`network.mainnet_keyring_backend_unsupported`. The headless store keeps every
entry, the audit log's tip anchor among them, in one file with no freshness
witness, so an older copy of that file restored beside a truncated audit log
agrees with it.

### Generate a headless keyring key

Generate the key once and store it in your secret manager. Reuse it for every
process that opens the same keyring store.

POSIX shell:

```sh
export STELLAR_AGENT_HEADLESS_KEYRING_KEY="$(openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=\n')"
```

PowerShell:

```powershell
$keyBytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $rng.GetBytes($keyBytes)
    $env:STELLAR_AGENT_HEADLESS_KEYRING_KEY = [Convert]::ToBase64String($keyBytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')
} finally {
    $rng.Dispose()
    [Array]::Clear($keyBytes, 0, $keyBytes.Length)
}
```

### Profile locations

Profiles live in the OS-conventional directory, one TOML file per profile name:

| Platform | Path |
|----------|------|
| Linux    | `~/.local/share/stellar-agent/profiles/<name>.toml` |
| macOS    | `~/Library/Application Support/Soneso.stellar-agent/profiles/<name>.toml` |
| Windows  | `%LOCALAPPDATA%\Soneso\stellar-agent\data\profiles\<name>.toml` |

The default profile name is `default`. The `balances` command takes an
explicit `--account` and `--rpc-url` (defaulting to the testnet RPC), and
`pay` reads its endpoint from the profile, so both work without authoring a
profile file. When no profile is *named* and no `default.toml` exists,
`stellar-agent-mcp` startup and commands such as `pay`, `claim`, and
`accounts create` use an in-memory testnet profile. `profile show` never uses
that fallback: it reads the profile file, so it exits `1` on a clean install.
The fallback never replaces a profile you name with `--profile` or
`STELLAR_AGENT_PROFILE`. If the named profile's file does not exist, the
command refuses.

To create a persistent profile, run `profile init`:

```bash
stellar-agent profile init
```

This writes `<profile_dir>/default.toml` with `engine = "v1"` (the default)
and placeholder signer/nonce keyring coordinates. The full setup flow is:

1. `profile init`: create the profile file (this step).
2. `profile rotate-audit-key`: mint the audit chain-root key, required on every
   engine. The key must exist before signer enrollment so its audit row is written.
   Every signing verb refuses `audit.chain_key_unavailable` until this runs.
3. [`profile enroll-signer`](#enroll-the-mcp-signer): register the MCP signer seed.
4. `stellar-agent profile rotate-nonce-key default`: mint the nonce key before
   MCP payment simulation. Without it, simulation fails with `nonce.mint_failed`.
5. For `v1`, run `profile enroll-owner-key`, then `profile rotate-attestation-key`.
6. [Create the V1 policy file](#create-the-v1-policy-file), then run
   `profile sign-policy`. See [Opt in to V1](profiles.md#opt-in-to-v1).

Pass `--profile <NAME>` for a non-default profile, `--rpc-url <URL>` to
override the testnet default. Pass `--network mainnet --rpc-url <URL>` for a
mainnet profile. Mainnet has no default endpoint, so it requires an explicit
`https://` `--rpc-url` with no username or password. Pass `--engine noop` to
skip the V1 owner-key ceremony for now. See [`profile
init`](cli-reference/profile-and-governance.md#profile-init) for the full
flag reference.

Every profile-aware command takes the same `--profile <NAME>`, and so does the
MCP server (`stellar-agent-mcp --profile <NAME>`); `STELLAR_AGENT_PROFILE` in
the environment sets the name for both when you omit the flag. A profile file
belongs to its name: back it up freely, but restoring it under a different file
name does not create a second profile. Run `profile init` for that.

On a `v1` profile, the MCP server starts once the owner key is enrolled and
the owner-signed policy loads; until then it refuses and names what is
missing. An approval also requires `profile rotate-attestation-key`. A testnet
profile created with `--engine noop` supports server startup and read access at
once. Mint the audit key with `profile rotate-audit-key` before `profile enroll-signer`
so enrollment writes its audit row. Then run `profile rotate-nonce-key` before
MCP payment simulation.

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
with the enrolled seed's derived address.
[Enroll the MCP signer](#enroll-the-mcp-signer) shows how to pin the signer
identity to an address in advance. The `account` field on the other entries is
only a keyring coordinate label and may stay `"default"`.

The `[policy] engine` value is `noop` or `v1`. Both engines require
`profile rotate-audit-key` before any signing verb proceeds. That
requirement is independent of the policy engine.

- `noop`: the Noop engine: testnet allow-all; on mainnet it allows read-only
  commands and refuses destructive ones with `policy.engine_required`.
  `smart-account multicall` requires `v1` and refuses a Noop profile with
  `policy.engine_required`.
- `v1`: the V1 engine: a signature-verified, typed-criteria, first-match
  default-deny engine. Beyond the audit key, the V1 engine requires the owner
  public key enrolled (`profile enroll-owner-key`), the attestation keyring key
  (`profile rotate-attestation-key`), and a policy file signed with
  `profile sign-policy`. Enable it only after that setup.

A version-2 profile must declare a `[policy]` block explicitly. There is no
silent default: the loader refuses a v2 file without one. The example profile
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

### Create the V1 policy file

Before `profile sign-policy`, create `policies/<name>.toml` in the wallet's
state directory. The default paths are:

| Platform | Policy file for `default` |
|----------|---------------------------|
| Linux | `${XDG_DATA_HOME:-$HOME/.local/share}/stellar-agent/policies/default.toml` |
| macOS | `~/Library/Application Support/Soneso.stellar-agent/policies/default.toml` |
| Windows | `%LOCALAPPDATA%\Soneso\stellar-agent\data\policies\default.toml` |

Create the parent directory first. On Linux or macOS:

```sh
case "$(uname -s)" in
  Linux) policy_dir="${XDG_DATA_HOME:-$HOME/.local/share}/stellar-agent/policies" ;;
  Darwin) policy_dir="$HOME/Library/Application Support/Soneso.stellar-agent/policies" ;;
esac
mkdir -p "$policy_dir"
```

On Windows PowerShell:

```powershell
$policyDir = Join-Path $env:LOCALAPPDATA 'Soneso\stellar-agent\data\policies'
New-Item -ItemType Directory -Force -Path $policyDir | Out-Null
```

Save this minimal policy as `default.toml` in that directory, using UTF-8:

```toml
version = 1
scope = "profile:default"

[[rules]]
match = { tool = "stellar_balances", chain = "*" }
criteria = []
decision = "allow"

[[rules]]
match = { tool = "stellar_pay", chain = "stellar:testnet" }
criteria = [{ kind = "per_period_cap", asset = "native", window = "1d", max_stroops = 1000000000 }]
decision = "allow"

[[rules]]
match = { tool = "stellar_pay_commit", chain = "stellar:testnet" }
criteria = [{ kind = "per_period_cap", asset = "native", window = "1d", max_stroops = 1000000000 }]
decision = "allow"

[[rules]]
match = { tool = "*", chain = "*" }
criteria = []
decision = "require_approval"
```

For another profile, replace `default` in the filename and `scope`.
Balance reads are allowed, and testnet payments are allowed up to 100 XLM per day.
An MCP payment needs both payment rules: `stellar_pay` builds and simulates it,
`stellar_pay_commit` signs and submits it, and each phase matches rules under
its own tool name.
Everything else waits for operator approval.
Review the rules before signing. See [policy rules](concepts.md#the-policy-engine)
for additional restrictions.

Then run `stellar-agent profile sign-policy --profile default --secret-env WALLET_OWNER_SK`
with the enrolled owner's seed in `WALLET_OWNER_SK`.
[Pass a secret seed](#pass-a-secret-seed) covers setting and
clearing that variable. The command adds the signature table; it refuses a
missing file with `sign_policy.policy_file_unreadable`.

### Set up mainnet writes

Use a build whose version marker is `STELLAR_AGENT_BUILD_MAINNET_WRITE=on`.
Create a dedicated mainnet profile with its HTTPS endpoint stored in the file.
Initialize the audit, nonce, attestation, and policy-owner keys, then enroll the
signer with `profile enroll-signer --secret-env`.

Run `profile enable-mainnet --profile <NAME>` to bind this installation.
Complete the [v2 policy body](profiles.md#mainnet-policy-body), including rules
for each prepare and commit name. Run `profile sign-policy`, then
`profile enable-mainnet --check`, and restart the MCP server.
[The command reference](cli-reference/profile-and-governance.md#profile-enable-mainnet)
owns ceremony flags and recovery.

Engine `v1` evaluates the signed policy body. Policy-body version 2 carries
mainnet bindings and a sequence. Profile-schema version 2 describes the
configuration file. These versions are independent.

## Pass a secret seed

Signing commands read a secret seed from the environment variable that
`--secret-env` names. Read the seed without echo, export it only for the
commands that need it, and unset it afterward. A seed typed into a command line
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

If you hold no account yet, `accounts create` generates one and funds it in a
single step. `--generate` mints a fresh ed25519 keypair in-process and returns
both the G-strkey and the secret in the JSON envelope (the secret in
`data.secret_key`, never in `--output table` and never logged).
`--fund-with-friendbot` funds it from Friendbot (testnet only):

```bash
stellar-agent accounts create --generate --fund-with-friendbot
```

Save the printed secret; the [enroll](#enroll-the-mcp-signer) and
[payment](#make-a-first-payment-on-testnet) steps read it. The command output
holds the seed, so do not write it to a log or a shared terminal.

To fund an account you already hold, call Friendbot directly. Friendbot pays an
existing account only while its XLM balance is below the Friendbot starting
balance, 10,000 XLM on the SDF testnet, and the command exits `1` with
`network.friendbot_account_already_funded` otherwise. Mainnet is structurally
refused (`network.friendbot_mainnet_forbidden`) before any HTTP call.

```bash
stellar-agent friendbot --account GABC...WXYZ --network testnet
```

Flags:

- `--account <G_STRKEY>`: the account to fund (required).
- `--network <NETWORK>`: `testnet` (default) or `futurenet`. The command
  rejects `mainnet` at dispatch.
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
minted (`profile rotate-audit-key <name>`, step 2 of the flow in
[Set up a profile](#set-up-a-profile)); before that they refuse
`audit.chain_key_unavailable`.

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
other seed, set `account` to that G-strkey yourself before enrolling.
Enrollment then refuses a seed that derives to another address and leaves
`account` unchanged.

Flags:

- `--secret-env <VAR>`: name of the environment variable holding the signer's
  S-strkey. The flag takes the variable name, never the secret.
- `--profile <NAME>`: profile whose `mcp_signer_default` entry is written
  (default `default`).
- `--expected-address <G_STRKEY>`: optional guard; enrollment refuses unless the
  seed derives to this address.
- `--force`: replace an already-enrolled entry.

The JSON envelope reports the derived `public_address`, the keyring coordinate
written, and `account_populated` (`true` when enrollment filled in a
placeholder, `false` when the account already pinned an identity). If the
profile's `account` already pins a *different* G-strkey than the derived
address, enrollment refuses. The command prints the address to set `account`
to.

## Check a balance

`balances` shows the XLM balance and the trustline balances of an account. It
is read-only; it makes no key access and does not sign. It queries the Stellar
RPC endpoint (not Horizon).

```bash
stellar-agent balances --account GABC...WXYZ
```

`balances` keeps its testnet endpoint default. Transaction commands instead read endpoints from their resolved profile.

Flags:

- `--account <G_STRKEY>`: the account to query (required).
- `--rpc-url <URL>`: Stellar RPC endpoint; defaults to
  `https://soroban-testnet.stellar.org`.
- `--asset <CODE:ISSUER>`: a trustline asset to query alongside XLM;
  repeat to query several. The output omits assets the account does not trust.
- `--output <FORMAT>`: `json` (default) or `table`.

```bash
stellar-agent balances \
  --account GABC...WXYZ \
  --asset USDC:GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5
```

The example names the testnet USDC issuer, and mainnet USDC has a different one.

## Make a first payment on testnet

`pay` sends a payment. By default it builds, signs, and submits the transaction
atomically, then polls until confirmation. It enforces SEP-29 memo-required
destinations before signing. The sample policy allows this payment within its
daily cap of 100 XLM.

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
- `<AMOUNT>` (positional), amount with units, for example `"10 XLM"` or
  `"10.5 USDC"`.
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

For the `--secret-env` path, the wallet loads the 32-byte signing seed into the
unlock window: a short TTL-bounded period during which the seed stays in
pinned, zeroize-on-drop memory (mlock). The TTL is the profile's `[wallet]
unlock_ttl_seconds` (default 30 seconds). It must be in the range 1 to 600
seconds. The wallet refuses a value of 0 or more than 600 when it builds the
window, and never clamps it. The profile's `[wallet] mlock_required` governs
what happens if the wallet cannot pin the seed in RAM: `true` (the default on
Linux/macOS) fails the signing call closed. The window is active only for the
duration of a single signing call. On every exit path, the wallet zeroizes the
seed and releases the lock. The `--sign-with-ledger` path holds no seed in
memory.

### Staged pipeline

You can run the stages independently. The flags are mutually exclusive:

- `--build-only`: emit the unsigned envelope XDR and exit (no signing).
- `--sign-only <BASE64_XDR>`: sign a built envelope and emit signed
  XDR.
- `--submit-only <BASE64_XDR>`: submit a signed envelope.

Under a V1 policy, `--sign-only` and `--submit-only` match rules under the
`stellar_pay_commit` tool name, the same name the MCP commit phase matches. The
[sample policy](#create-the-v1-policy-file) names it. A ruleset that names only
`stellar_pay` refuses the staged flows, as the policy entry of
[`stellar-agent pay`](cli-reference/stellar-ops.md#stellar-agent-pay-destination-amount-asset-flags)
in the CLI reference states.

`--use-oz-relayer` is an opt-in that is not implemented in this build: it prints
an AGPL-3.0 disclosure to stderr and declines with
`validation.relayer_not_implemented`. See the [CLI reference](cli-reference/index.md)
for the full flag set.

## Mainnet configurations and scope

Released binaries have `mainnet-write` disabled. A build with the feature enabled
admits only the operations listed below after operator setup and approval for
each action. The version marker reports the build configuration.

Mainnet writes move real funds. The wallet is alpha software and comes without
warranty under the Apache-2.0 license. Use a feature-enabled build on mainnet at
your own risk. Test each flow on testnet first, and start with small amounts and
tight policy limits.

With the feature off, no code path in the shipped binary can satisfy the
mainnet-write guard, and the binary attests its feature state.

The guarantee has one precondition: the claim holds only under the dependency
set pinned and verified by the release.

| Configuration | Behavior | Admitted operations | Exclusions | Preconditions and outcomes |
|---|---|---|---|---|
| `mainnet-write` off | Refuses mainnet signing and transaction writes. Reports `STELLAR_AGENT_BUILD_MAINNET_WRITE=off`. | None. | Every mainnet signing and transaction-write surface. | Setup cannot change the compiled feature state. Wallet guards report `network.mainnet_write_forbidden`. Excluded protocols retain their documented codes. |
| `mainnet-write` on, classic CLI | Authorizes each supported action before signing and submission. Reports `STELLAR_AGENT_BUILD_MAINNET_WRITE=on`. | Full-mode `pay`, `claim`, sponsored `accounts create`, and `trustline`. | Build-only, sign-only, submit-only, Friendbot creation, `accounts create --generate`, relayer paths, and the excluded surfaces below. | Requires an explicit nondefault mainnet profile, matching stored configuration, enrolled identities, enablement, an owner-signed v2 policy, valid pin and audit state, required witness, and confirmation. |
| `mainnet-write` on, classic MCP | Authorizes each supported commit before signing and submission. | `stellar_pay_commit`, `stellar_claim_commit`, `stellar_create_account_commit`, and `stellar_trustline_commit`. | Other generic signing tools, toolset signing actions, and the excluded surfaces below. | Requires the same installation and policy checks, plus approval bound to the action. Both prepare and commit policy names need matching rules. |
| Classic failure classification | Reports the boundary that refused the action. | No admission follows from an error code. | A policy decision alone does not authorize signing. | Structural and context refusals use `network.mainnet_write_forbidden`. CLI engine construction preserves enablement errors and wraps other failures as `policy.engine_unavailable` or `trustline.policy_engine_unavailable`. Resolver setup gaps use `network.mainnet_authorization_refused`. Policy denials retain `policy.deny.*`. |
| `mainnet-write` on, x402 | Releases an authorized payment payload through the supported flow. | `stellar_x402_create_payment`; `stellar_x402_authenticated_payment`, including its bound SEP-10 identity operation. | Generic SEP-10 signing, generic message signing, and unrelated Soroban operations. | Requires installation binding, signed policy, payment approval, required witness, authorized signing, and authorized payload release. Authenticated payments also bind the identity operation. |
| `mainnet-write` on, excluded operation | Refuses the operation on mainnet. | None. | Smart-account deployment and writes; rules, signers, policies, execute, multicall, migration-submit, and timelock writes; DeFi; pool submission; MPP; public SEP-43 signing; generic SEP-45/53 signing; fee bumps; idempotent mainnet submission. | Ceremony, policy, and approval do not admit these operations. MPP uses `mpp.network_forbidden`. Wallet and library interfaces retain their documented refusal codes. |
| Either build, read or local operation | Applies the operation's profile, policy, audit, and protocol requirements. | No transaction-write admission follows from a read or local operation. | Read-only classification does not override a protocol refusal. | Mainnet selection and key-scope checks apply. Noop allows mainnet reads and refuses destructive actions with `policy.engine_required`. |

On an admitted mainnet MCP server, the four classic prepare and commit pairs
require approval even when the matching rule allows the action. Both x402
payment tools also require approval under an Allow rule. On mainnet, their first
call returns pending approval without a payment payload. Repeat the call with
both approval arguments after CLI approval. The server
loads the mainnet write context at startup when the selected profile has a
verified enablement record. If enablement or policy fails startup checks, the
server does not start.

After `profile enable-mainnet` or `profile sign-policy`, restart the MCP server.
A changed startup binding refuses with `network.mainnet_write_forbidden` and
`enablement or policy changed, restart the server`. Missing startup authority
instead names the missing prerequisite.

Report an authorization refusal to the operator. The operator reads the failed
check in the `precondition` field of the warn-level log entry
`mainnet authorization refused`. For missing enablement, run
`profile enable-mainnet`, complete the policy, then run `profile sign-policy`.
Then restart the MCP server. CLI entry checks can refuse missing engine,
verified policy, or enablement before the resolver runs.

Ledger and `--secret-env` signers must satisfy the enrolled-identity requirement.
`profile enroll-signer` accepts `--secret-env` only and cannot enroll a Ledger
key. Classic approvals support the CLI, approval-ui, and approval-remote
attestation surfaces. CLI `approve` requires a terminal and refuses `--yes` on
mainnet. Direct CLI confirmation requires the exact typed profile name.

See [Mainnet write behavior](cli-reference/index.md#mainnet-write-behavior),
[Mainnet policy body](profiles.md#mainnet-policy-body), and
[the enablement ceremony](cli-reference/profile-and-governance.md#profile-enable-mainnet).
The wallet's own signing paths sign mainnet payloads only under mainnet
authorization. Library signing primitives do not enforce this requirement.
Code running as the same OS user with access to a keyring entry can read its
seed directly. The keyring entry is the custody boundary.
Authorized signing and submission independently verify sealed authority.
Submission binds envelope signatures to the endpoint's network.

### Mainnet refusal order

A mainnet write passes four states in this order: nothing sent or signed,
unsigned requests sent, signed locally, signed material sent. The states refer
to the transaction or payment signature. Authenticated x402 also signs and
submits a SEP-10 challenge with an ephemeral key inside the second state. Each
row names the checks that can refuse in that state, grouped by class, and the
codes they report. Inside a row, the order of the checks differs by command and
tool.

| State when a check refuses | Checks, by class | Codes |
|---|---|---|
| Nothing sent or signed | Entry: the compiled feature, an explicit nondefault mainnet profile with matching stored configuration, full mode and keyring access (CLI), envelope and address decoding (classic MCP). Policy: the V1 engine; classic MCP and x402 also check the verified policy and enablement here. URL: client construction and its credential (CLI, classic MCP, plain x402). x402: call 1 ends here. Plain x402 call 2 sends nothing before the payment build. Its checks up to there: requirements, `chain_id`, the approval pair, enrollment and address, local policy evaluation, forced approval, the attestation, audit readiness, the signing handle. Authenticated x402 call 2 runs the same checks through the attestation, plus the home domain, the audit pre-flight, and identity audit readiness. It leaves this state at the identity exchange. | `network.mainnet_write_forbidden`, profile and validation codes, keyring codes, `network.rpc_unreachable`, `network.rpc_credential_refused`, `simulation.divergence` (classic MCP), JSON-RPC invalid params, `x402.*` requirement codes, `identity.home_domain_invalid`, `policy.approval_required`, `policy.approval_rejected`, `policy.approval_consumed`, `policy.deny.*`, `policy.engine_required`, `policy.unexpected_decision`, `auth.enrolled_*`, `audit.*`, approval-store codes |
| Unsigned requests sent: the endpoint identity probe, account and chain reads, the oracle simulation, the unsigned payment simulation (x402) | URL: endpoint identity, protocol version. Entry: the remaining input decoding (CLI, classic MCP). Policy: the verified policy and enablement (CLI), the rebuilt envelope (classic MCP), the policy evaluation, the fee cap and the operation conditions (CLI, classic MCP), the required witness, the health read (x402). Authorization: the attestation or the terminal confirmation, audit readiness, the nonce, signer enrollment, the resolver's sealed checks (CLI, classic MCP); the payment intent authorization (x402). Authenticated x402: the bound SEP-10 authentication runs in this state, and its signed challenge reaches the web-auth server before the payment checks. Payment audit readiness, the signing handle, the payment asset, and client construction follow it. | `network.endpoint_network_mismatch`, `network.endpoint_identity_unavailable`, `network.unsupported_protocol_version`, `network.rpc_credential_refused`, `network.rpc_unreachable` (authenticated x402), read codes, keyring codes, `simulation.divergence`, `network.mainnet_write_forbidden` (CLI), `profile.mainnet_enablement_invalid`, `policy.engine_unavailable`, `trustline.policy_engine_unavailable`, `policy.deny.*`, `policy.engine_required`, `policy.unexpected_decision`, fee-cap codes, `trustline.*`, `network.witness_unavailable`, `confirm.*`, `policy.approval_required`, `policy.approval_rejected`, `policy.approval_consumed`, `audit.*`, `nonce.*`, `auth.enrolled_*`, `identity.*`, `x402.rpc_simulate_failed`, `x402.unexpected_auth_entries`, `x402.invalid_asset_address` (authenticated x402), `x402.payment_build_failed` (authenticated), `network.mainnet_authorization_refused` |
| Signed locally, no signed material sent | Authorization: the signer and the signature check. Submission (CLI, classic MCP): the shared checks before the send: authorization, envelope shape, endpoint identity recheck, signature network binding, transaction hash, pre-send record, consumption proof. x402: the entry signature, the audit row, and the intent consumption before the re-simulation. | `network.mainnet_authorization_refused`, keyring and signer codes, `audit.*`, `protocol.xdr_codec_failed`, endpoint and protocol codes, `submission.record_unavailable`, `submission.tx_already_submitted`, `policy.deny.*`, `x402.transaction_build_failed`, `x402.payment_build_failed` (authenticated) |
| Signed material sent | Submission (CLI, classic MCP): the send and the confirmation; reconcile an unknown outcome. x402: the signed re-simulation sends the signed authorization to the configured RPC. After it, the re-simulation answer checks, the release authorization, the payload encoding, the release consumption, and the pending-approval consumption withhold the payload. | `submission.*`, `x402.rpc_simulate_failed`, `x402.transaction_build_failed`, `x402.unexpected_auth_entries`, `x402.payment_build_failed` (authenticated), encoding codes, approval-store codes, `network.mainnet_authorization_refused` (payload withheld) |

A code can appear in more than one row. For the plain x402 tool, the message
prefix names the stage: `payment withheld before signed transmission`,
`at intent transmit gate`, `after intent authorization`, `at payload encoding`,
`at payload release`, or `at terminal approval`. A withheld payment payload
does not mean the configured RPC saw no signed authorization. For authenticated
x402, a refusal after the identity exchange does not mean the web-auth server
saw nothing: the wallet can already have submitted the signed SEP-10 challenge.

## Next steps

- [Concepts](concepts.md): the profile, the unlock window, the policy engine
  with its criteria, the approval spine with its attestation, the audit log,
  and smart-account context rules.
- [CLI reference](cli-reference/index.md): every subcommand, flag, and default.
- [MCP server](mcp.md): running `stellar-agent-mcp` as an MCP stdio server.
- [Profiles](profiles.md): the full profile schema and the key-rotation
  ceremony.
