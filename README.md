<p align="center">
  <img src="docs/assets/banner.svg" alt="Stellar Agent Wallet banner" width="100%">
</p>

<p align="center">
  <a href="https://github.com/Soneso/stellar-agent-wallet/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Soneso/stellar-agent-wallet/ci.yml?branch=main&style=for-the-badge&label=CI" alt="CI status"></a>
  <a href="https://crates.io/crates/stellar-agent-cli"><img src="https://img.shields.io/crates/v/stellar-agent-cli?style=for-the-badge&label=crates.io" alt="crates.io version"></a>
  <a href="https://github.com/Soneso/stellar-agent-wallet/releases"><img src="https://img.shields.io/github/v/release/Soneso/stellar-agent-wallet?include_prereleases&style=for-the-badge&label=release" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/Soneso/stellar-agent-wallet?style=for-the-badge" alt="License"></a>
  <a href="docs/getting-started.md"><img src="https://img.shields.io/badge/docs-getting_started-4cc9f0?style=for-the-badge" alt="Getting started"></a>
  <a href="https://github.com/Soneso/stellar-agent-wallet/issues?q=is%3Aissue+is%3Aopen+label%3Aagent-ready"><img src="https://img.shields.io/github/issues/Soneso/stellar-agent-wallet/agent-ready?style=for-the-badge&label=agent-ready%20issues" alt="Open agent-ready issues"></a>
  <a href="https://soneso.com"><img src="https://img.shields.io/badge/maintained_by-Soneso-243b5c?style=for-the-badge" alt="Maintained by Soneso"></a>
</p>

# Stellar Agent Wallet

A Stellar wallet for AI agents, built by AI agents: autonomous transactions
inside rules you define, approvals you grant, and an audit trail you can verify.

Stellar Agent Wallet is a community experiment. AI agents write most of the
code, a maintainer reviews every pull request, and anyone who works with agents
on Stellar can contribute. Soneso maintains the project under
[GOVERNANCE.md](GOVERNANCE.md).

`stellar-agent-wallet` lets an AI agent transact on Stellar under guardrails. It
ships two surfaces over one shared core: the `stellar-agent` CLI, which also runs
as `stellar agent` inside the Stellar CLI, and the `stellar-agent-mcp` MCP stdio
server. Both sit on a policy engine, an operator-approval spine, and a
tamper-evident hash-chained audit log, so an autonomous agent can act while a
human keeps control of what it is allowed to do.

New to the project? [What is the Stellar Agent Wallet?](docs/onboarding.md)
is the non-technical tour: what it is, what an agent can do with it, and how a
first session with Claude Code looks.

## Status

Public alpha, under active development. The
[milestones](https://github.com/Soneso/stellar-agent-wallet/milestones) list
the planned work per release.

- testnet (`stellar:testnet`) is the default network: a command with no
  named profile and no `default.toml` runs on the zero-config testnet profile.
- mainnet (`stellar:mainnet`) is read-only in this alpha. Every write or
  signing command refuses a mainnet profile, and the submit layer refuses a
  mainnet endpoint after asking it which network it serves.
  [Mainnet is refused for writes](docs/getting-started.md#mainnet-is-refused-for-writes)
  lists the commands, the layers, and the wire codes.
- Friendbot funding is testnet/futurenet only; mainnet is structurally refused.

Release archives are published on the
[releases page](https://github.com/Soneso/stellar-agent-wallet/releases) for
each tagged release, and the workspace crates are published to
[crates.io](https://crates.io/crates/stellar-agent-cli) with each release
(features merged since the last tag ship from source until the next one).

## Highlights

- Payments and assets: payments, balances, trustlines, and claimable-balance
  claims on Stellar.
- DeFi: adapters for Soroswap swaps (CLI `trade`; MCP
  `stellar_dex_trade` plus read-only `stellar_dex_quote`) and DeFindex vaults
  (`vault`). Each verb is typed, simulate-checked, and
  fail-closed; raw or opaque calldata is refused before signing.
- Smart accounts:
  - OpenZeppelin smart-account governance: deployment, context rules, threshold
    updates, and WebAuthn passkey signers, with signing bound to the on-chain
    authorization rules. Each non-zero authorizing rule passes the signer-set
    comparison and executable pin check before signing.
  - Bounded agent delegation: scoped context rules (`CallContract` /
    `CreateContract`) and rolling-window spending limits. A first-class
    External-Ed25519 signer lets an agent hold its own key and submit
    smart-account `execute` calls within limits the contract enforces on-chain.
- Anchors and protocols over SEP: SEP-6 and SEP-24 anchor flows, SEP-7
  `web+stellar:` URI parsing, SEP-10 web auth, SEP-43 wallet signing, and
  SEP-45 contract-account web auth. The wallet also supports SEP-47
  contract-interface discovery, SEP-48 typed-argument preview, and SEP-53
  prefixed message signing.
- Machine payments:
  - x402 agent payments: payer-side `PAYMENT-SIGNATURE` payloads for the x402 v2
    Exact Stellar scheme, with an optional SEP-10 counterparty-identity gate.
  - Machine Payments Protocol (MPP) sponsored charges: strict HTTP/native-MCP
    challenge validation, one-shot G-account authorization, host receipts, and
    independent settlement reconciliation. This credential-only flow is
    testnet-only; the trusted host sends the paid request and server submission.
- Operator control:
  - Operator approval loop with a terminal command and a loopback web inbox
    (list, notify, approve, or reject pending agent actions).
  - Signed agent toolsets with capability isolation: toolsets are installed
    only after publisher-signature and hash verification. A structural boundary
    keeps a toolset from reaching a signing tool it was not granted.
  - Interactive passkey enrollment for the operator approval surfaces: register
    a WebAuthn credential for the loopback or remote approval inbox with a local
    one-shot browser ceremony.
  - Ledger signing: `--sign-with-ledger` uses a connected Ledger hardware device
    to sign, and `--account-index` selects the BIP-44 account index for the
    derivation path.

See [docs/concepts.md](docs/concepts.md) for the policy engine, approval spine,
audit log, and toolset model in detail.

The supported MPP flow, exact trust boundary, CLI commands, and five MCP tools
are documented in [Agent payments with MPP](docs/agent-payments.md).

## Contribute with your agent

Give your coding agent [`AGENTS.md`](AGENTS.md); it tells the agent where to
start. Issues labeled
[`agent-ready`](https://github.com/Soneso/stellar-agent-wallet/issues?q=is%3Aissue+is%3Aopen+label%3Aagent-ready)
carry the file, an acceptance check, and the gate commands. Claim an unassigned
[`good first issue`](https://github.com/Soneso/stellar-agent-wallet/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
or
[`help wanted`](https://github.com/Soneso/stellar-agent-wallet/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
by commenting "I'll take this". Merged pull requests get release-note credit.
[CONTRIBUTING.md](CONTRIBUTING.md#start-here-with-your-agent) has a starter
prompt for your agent and describes the review path, and questions and ideas go
to [Discussions](https://github.com/Soneso/stellar-agent-wallet/discussions).

## Install

Prebuilt binaries are published on the
[releases page](https://github.com/Soneso/stellar-agent-wallet/releases) for each
tagged release, and the crates are published to crates.io with each release.

While only prerelease (alpha) versions are published, `cargo install` and
`cargo binstall` need the version spelled out. A bare crate name matches
stable versions only.

### cargo binstall (prebuilt binaries)

`cargo binstall` resolves the crate on crates.io and downloads the prebuilt
release archive from the tagged release assets:

```bash
cargo binstall --locked --disable-strategies quick-install,compile stellar-agent-cli@0.1.0-alpha.10 stellar-agent-mcp@0.1.0-alpha.10
```

Release archives exist for the five targets that
[Prebuilt binaries](docs/getting-started.md#prebuilt-binaries-cargo-binstall)
lists. `cargo binstall` installs the archive for the host's target, or for a
compatible target the host runs, such as the x86_64 Windows archive under
emulation. With `--disable-strategies quick-install,compile`, it fails when no
such archive exists; on other hosts, use `cargo install --locked` or build from
source. `--locked` applies when binstall builds from source, which the strategy
flag turns off. The strategy flag needs cargo-binstall 0.17.0 or later.

The CLI and MCP binaries ship in one release archive
(`stellar-agent-{version}-{target}.tar.xz`, or `.zip` on Windows), so both
installs draw from the same download. You can also fetch and extract the
archive directly, without any Rust tooling (substitute your target, for example
`aarch64-apple-darwin` or `x86_64-unknown-linux-gnu`):

Linux or macOS (this example selects Apple Silicon):

```bash
curl -fsSLO https://github.com/Soneso/stellar-agent-wallet/releases/download/v0.1.0-alpha.10/stellar-agent-0.1.0-alpha.10-aarch64-apple-darwin.tar.xz
curl -fsSLO https://github.com/Soneso/stellar-agent-wallet/releases/download/v0.1.0-alpha.10/SHA256SUMS
```

On Linux, check the checksum with `sha256sum --ignore-missing --check SHA256SUMS`.
On macOS, use `shasum -a 256 --ignore-missing --check SHA256SUMS`.
After the checksum matches, extract the archive and add its folder to this
shell's `PATH`:

```bash
tar -xJf stellar-agent-0.1.0-alpha.10-aarch64-apple-darwin.tar.xz
export PATH="$PWD/stellar-agent-0.1.0-alpha.10-aarch64-apple-darwin:$PATH"
```

Windows PowerShell:

```powershell
$release = 'https://github.com/Soneso/stellar-agent-wallet/releases/download/v0.1.0-alpha.10'
$folder = 'stellar-agent-0.1.0-alpha.10-x86_64-pc-windows-msvc'
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
Every Linux, macOS, and Windows archive extracts into
`stellar-agent-<version>-<target>/`. Both binaries are inside that folder;
the Windows names end in `.exe`.

The release signs the macOS
binaries with a Developer ID and notarizes them. A bare executable carries no
stapled ticket, so Gatekeeper checks notarization online. The
[macOS Gatekeeper note](docs/getting-started.md#macos-gatekeeper-note) shows how
to check the signature and the notarization.

### cargo install (from crates.io)

Builds the binaries from the published sources:

```bash
cargo install --locked stellar-agent-cli@0.1.0-alpha.10 stellar-agent-mcp@0.1.0-alpha.10
```

`--locked` makes cargo build with the `Cargo.lock` published in the crate.
This installs the `stellar-agent` and `stellar-agent-mcp` executables. Building
requires the stable Rust toolchain (edition 2024).

### Build from source

```bash
git clone --branch v0.1.0-alpha.10 https://github.com/Soneso/stellar-agent-wallet.git
cd stellar-agent-wallet
cargo build --release --locked
```

The clone checks out the release tag, and `--locked` builds with its committed
`Cargo.lock`. The binaries land at `target/release/stellar-agent` and
`target/release/stellar-agent-mcp`.

The CLI is also discoverable as `stellar agent ...` through the `stellar-cli`
external-binary plugin convention when `stellar-agent` is on your `PATH`.

### Verifying a release

`cargo binstall` checks the GitHub release download over TLS only, with no
signature. Every release also publishes a `SHA256SUMS` manifest, a [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
keyless signature bundle per archive, and SLSA provenance, for anyone who
wants to verify further.

Download `SHA256SUMS` from the same release as the archive. On Linux:

```bash
sha256sum --ignore-missing --check SHA256SUMS
```

On macOS, use `shasum -a 256 --ignore-missing --check SHA256SUMS`.
The Windows PowerShell example under [cargo binstall](#cargo-binstall-prebuilt-binaries)
compares `Get-FileHash -Algorithm SHA256` with the archive's entry in `SHA256SUMS`
before calling `Expand-Archive`.

Cosign signature (keyless; verifies the archive was signed by this
repository's release workflow, not by an arbitrary identity):

```bash
cosign verify-blob \
  --bundle stellar-agent-<version>-<target>.tar.xz.sigstore.json \
  --certificate-identity "https://github.com/Soneso/stellar-agent-wallet/.github/workflows/release.yml@refs/tags/v<version>" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  stellar-agent-<version>-<target>.tar.xz
```

SLSA provenance, with [slsa-verifier](https://github.com/slsa-framework/slsa-verifier)
(checks the archive was built by this repository's release workflow from the
tagged commit):

```bash
slsa-verifier verify-artifact stellar-agent-<version>-<target>.tar.xz \
  --provenance-path stellar-agent-<version>.intoto.jsonl \
  --source-uri github.com/Soneso/stellar-agent-wallet \
  --source-tag v<version>
```

## 60-second quickstart

Generate and fund an account, check its balances, and send a payment. These
commands take an explicit account on the flags and need no profile.

Generate a fresh testnet keypair and fund it from Friendbot in one step:

```bash
stellar-agent accounts create --generate --fund-with-friendbot
```

The JSON output carries the new G-strkey and its secret (`data.secret_key`).
Save the printed secret; the payment in this quickstart reads it. The command
output holds the seed, so do not write it to a log or a shared terminal.

Read the new account's XLM and trustline balances:

```bash
stellar-agent balances --account GABC...WXYZ
```

The payment reads the seed from `WALLET_SK`. Run this line on its own, paste
the saved secret when prompted, and press Enter:

```bash
printf 'WALLET_SK seed: ' && read -rs WALLET_SK && echo && export WALLET_SK
```

Send a payment (the asset is positional and defaults to `native`), then
remove the seed from the shell:

```bash
stellar-agent pay GDEST...WXYZ "10 XLM" --source GABC...WXYZ --secret-env WALLET_SK
unset WALLET_SK
```

[Pass a secret seed](docs/getting-started.md#pass-a-secret-seed) covers
PowerShell and the cleanup of a seed typed into a command line.

`stellar-agent profile show default` requires an existing profile file and exits
`1` on a clean install. The synthesised in-memory testnet default is used by
`stellar-agent-mcp` startup and by `pay` / `claim` / `accounts create`, and
only when no profile was named and no `default.toml` exists, never by
`profile show`. Run
`stellar-agent profile init` to create `default.toml`. It writes
`engine = "v1"` by default. On a V1 profile, the MCP server starts once the
owner key is enrolled and the owner-signed policy loads. A testnet profile created with `--engine noop` supports
server startup and read access immediately. Run `profile rotate-nonce-key` before
MCP payment simulation. Before MCP signing, mint the audit key with
`profile rotate-audit-key` and enroll the signer with `profile enroll-signer`.

Commands print a JSON envelope on stdout by default and exit `0` on success or
`1` on any error. A profile holds no secrets: it binds a CAIP-2 chain
(`stellar:testnet` on disk), an RPC endpoint, keyring entry references,
thresholds, and the active policy engine.

See [docs/getting-started.md](docs/getting-started.md) for the full walkthrough
and [docs/cli-reference/index.md](docs/cli-reference/index.md) for every command,
flag, and output shape.

## Running the MCP server

`stellar-agent-mcp` is an MCP server spoken over stdio. Point an MCP client at
the binary:

```bash
stellar-agent-mcp
```

The server registers its tool families (payments, DeFi, SEP protocols, toolsets)
behind the same policy engine, approval spine, and audit log as the CLI. See
[docs/mcp.md](docs/mcp.md) for client configuration and the tool catalogue.

## Documentation

- [Documentation for users](docs/README.md#for-users): getting started,
  concepts, the CLI and MCP references, protocols, toolsets, profiles, and
  remote approval.
- [Documentation for maintainers](docs/README.md#for-maintainers):
  architecture, building and testing, security internals, and the review
  checklist.

## Agent skill

An [Agent Skill](https://agentskills.io) that teaches an AI agent how to operate
the wallet (CLI and MCP) without cloning this repository ships in
[`skills/`](skills/). Install it manually from
[`skills/stellar-agent-wallet.zip`](skills/stellar-agent-wallet.zip) or, in Claude
Code, via the marketplace:

```bash
/plugin marketplace add Soneso/stellar-agent-wallet
/plugin install stellar-agent-wallet@soneso-stellar-agent-wallet
```

This is distinct from the wallet's built-in
[toolsets feature](docs/toolsets.md) (signed, capability-restricting packages
the wallet enforces at runtime), demonstrated in
[`examples/toolsets/`](examples/toolsets/).

## Security

See [SECURITY.md](SECURITY.md) for the supported versions and how to report a
vulnerability.

## License

Apache-2.0. See [LICENSE](LICENSE).

---

"Stellar" is a trademark of the Stellar Development Foundation.
This is an independent project, not affiliated with, sponsored or endorsed by the Stellar Development Foundation.
