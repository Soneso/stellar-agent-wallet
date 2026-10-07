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

- Payments and assets: send payments, check balances, manage trustlines, and
  claim claimable balances on Stellar.
- DeFi: swap tokens on Soroswap, and deposit into or withdraw from DeFindex
  vaults.
- Smart accounts: deploy and govern OpenZeppelin smart accounts with WebAuthn
  passkey signers. Delegate to an agent that holds its own key, within scoped
  rules and spending limits the contract enforces.
- SEP protocols: the wallet supports SEP-6, SEP-7, SEP-10, SEP-24, SEP-43,
  SEP-45, SEP-47, SEP-48, and SEP-53. They cover anchor flows, payment URIs,
  web authentication, wallet signing, message signing, and contract interfaces.
- Machine payments: pay as an x402 client, and authorize Machine Payments
  Protocol (MPP) sponsored charges on testnet.
- Operator control: approve or reject pending agent actions from a terminal or
  a web inbox, enroll passkeys for the approval inboxes, install signed
  toolsets, and sign with a Ledger device.

[Concepts](docs/concepts.md) explains the policy engine, approval spine, audit
log, and toolset model. [Agent payments with MPP](docs/agent-payments.md)
documents the supported MPP flow, its trust boundary, the CLI commands, and the
five MCP tools. [Protocols and integrations](docs/protocols.md) details the
SEPs, x402, and the DeFi venues.

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

Each tagged release publishes prebuilt archives on the
[releases page](https://github.com/Soneso/stellar-agent-wallet/releases) and the
crates on crates.io. While only prerelease (alpha) versions exist,
`cargo install` and `cargo binstall` need the version spelled out, because a
bare crate name matches stable versions only.

### cargo binstall (prebuilt binaries)

`cargo binstall` downloads the prebuilt release archive for your platform:

```bash
cargo binstall --locked --disable-strategies quick-install,compile stellar-agent-cli@0.1.0-alpha.11 stellar-agent-mcp@0.1.0-alpha.11
```

### cargo install (from crates.io)

`cargo install` builds both binaries from the sources on crates.io:

```bash
cargo install --locked stellar-agent-cli@0.1.0-alpha.11 stellar-agent-mcp@0.1.0-alpha.11
```

### Build from source

Clone the release tag and build with its committed `Cargo.lock`:

```bash
git clone --branch v0.1.0-alpha.11 https://github.com/Soneso/stellar-agent-wallet.git
cd stellar-agent-wallet
cargo build --release --locked
```

The CLI is also discoverable as `stellar agent ...` through the `stellar-cli`
external-binary plugin convention when `stellar-agent` is on your `PATH`.

[Install](docs/getting-started.md#install) covers the direct download with its
checksum check, the Windows PowerShell steps, and the macOS Gatekeeper note.
[Verifying releases](docs/verifying-releases.md) shows how to check an archive
against its checksums, its cosign signature, and its SLSA provenance.

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

By default, commands print one JSON envelope on stdout and exit `0` on success
or `1` on any error. `stellar-agent profile init` creates a persistent profile,
which policies and MCP signing need, as
[Set up a profile](docs/getting-started.md#set-up-a-profile) describes.

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
