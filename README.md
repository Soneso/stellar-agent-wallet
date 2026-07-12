# Stellar Agent Wallet

A Stellar wallet for AI agents.

`stellar-agent-wallet` lets an AI agent transact on Stellar under guardrails. It
ships two surfaces over one shared core: the `stellar-agent` CLI and the
`stellar-agent-mcp` MCP stdio server. Both sit on a policy engine, an
operator-approval spine, and a tamper-evident hash-chained audit log, so an
autonomous agent can act while a human keeps control of what it is allowed to do.

New to the project? [What is the Stellar Agent Wallet?](docs/onboarding.md)
is the non-technical tour: what it is, what an agent can do with it, and how a
first session with Claude Code looks.

## Status

Public alpha, under active development.

- testnet (`stellar:testnet`) is the default network.
- mainnet (`stellar:mainnet`) is accepted for read-only commands, selected
  via `--network` where the command exposes it or via `--rpc-url` for
  `balances` (which has no `--network` flag). Every write or signing command
  structurally refuses mainnet in this alpha, before any RPC call or signing
  (wire code `network.mainnet_write_forbidden`).
- Friendbot funding is testnet/futurenet only; mainnet is structurally refused.

Release archives are published on the
[releases page](https://github.com/Soneso/stellar-agent-wallet/releases) for
each tagged release, and every workspace crate is published on
[crates.io](https://crates.io/crates/stellar-agent-cli).

## Highlights

- Payments, balances, trustlines, and claimable-balance claims on Stellar.
- Operator approval loop with a terminal command and a loopback web inbox
  (list, notify, approve or reject pending agent actions).
- DeFi adapters: Blend lending (`lend`), Soroswap swaps (CLI `trade`; MCP
  `stellar_dex_trade` plus read-only `stellar_dex_quote`), DeFindex vaults
  (`vault`). Each verb is typed, simulate-checked, and
  fail-closed; raw or opaque calldata is refused before signing.
- SEP protocol support: SEP-6 and SEP-24 anchor flows, SEP-7 `web+stellar:` URI
  parsing, SEP-10 web auth, SEP-43 wallet signing, SEP-45 contract-account web
  auth, SEP-47 contract-interface discovery, SEP-48 typed-argument preview, and
  SEP-53 prefixed message signing.
- x402 agent payments: payer-side `PAYMENT-SIGNATURE` payloads for the x402 v2
  Exact Stellar scheme, with an optional SEP-10 counterparty-identity gate.
- OpenZeppelin smart-account governance: deployment, context rules, threshold
  updates, and WebAuthn passkey signers, with signing bound to the on-chain
  authorization rules.
- Signed agent toolsets with capability isolation: toolsets are installed only
  after publisher-signature and hash verification, and a structural boundary keeps
  a toolset from reaching a signing tool it was not granted.
- Bounded agent delegation: scoped context rules (`CallContract` /
  `CreateContract`), rolling-window spending limits, and a first-class
  External-Ed25519 signer let an agent hold its own key and submit smart-account
  `execute` calls within limits the contract enforces on-chain.
- Interactive passkey enrollment for the operator approval surfaces: register a
  WebAuthn credential for the loopback or remote approval inbox with a local
  one-shot browser ceremony.

See [docs/concepts.md](docs/concepts.md) for the policy engine, approval spine,
audit log, and toolset model in detail.

## Install

Prebuilt binaries are published on the
[releases page](https://github.com/Soneso/stellar-agent-wallet/releases) for each
tagged release, and all crates are published on crates.io.

While only prerelease (alpha) versions are published, `cargo install` and
`cargo binstall` need the version spelled out — a bare crate name matches
stable versions only.

### cargo binstall (prebuilt binaries)

`cargo binstall` resolves the crate on crates.io and downloads the prebuilt
release archive for your target from the tagged release assets:

```bash
cargo binstall stellar-agent-cli@0.1.0-alpha.4 stellar-agent-mcp@0.1.0-alpha.4
```

The CLI and MCP binaries ship in one release archive
(`stellar-agent-{version}-{target}.tar.xz`, or `.zip` on Windows), so both
installs draw from the same download. You can also download the archive directly
from the [releases page](https://github.com/Soneso/stellar-agent-wallet/releases)
and extract the two binaries onto your `PATH`.

### cargo install (from crates.io)

Builds the binaries from the published sources:

```bash
cargo install stellar-agent-cli@0.1.0-alpha.4 stellar-agent-mcp@0.1.0-alpha.4
```

This installs the `stellar-agent` and `stellar-agent-mcp` executables. Building
requires the stable Rust toolchain (edition 2024).

### Build from source

```bash
git clone https://github.com/Soneso/stellar-agent-wallet.git
cd stellar-agent-wallet
cargo build --release
```

The binaries land at `target/release/stellar-agent` and
`target/release/stellar-agent-mcp`.

The CLI is also discoverable as `stellar agent ...` through the `stellar-cli`
external-binary plugin convention when `stellar-agent` is on your `PATH`.

### Verifying a release

`cargo binstall` trusts the GitHub release download over TLS only. Every
release also publishes a `SHA256SUMS` manifest, a [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
keyless signature bundle per archive, and SLSA provenance, for anyone who
wants to verify further.

Checksum:

```bash
sha256sum --ignore-missing --check SHA256SUMS
```

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

```bash
# Generate a fresh testnet keypair and fund it from Friendbot in one step.
# The JSON output carries the new G-strkey and its secret (data.secret_key).
stellar-agent accounts create --generate --fund-with-friendbot

# Export the printed secret so the signing command below can read it.
export WALLET_SK=S...printed-secret...

# Read the new account's native and trustline balances.
stellar-agent balances --account GABC...WXYZ

# Send a payment (asset is positional and defaults to native).
stellar-agent pay GDEST...WXYZ "10 XLM" --source GABC...WXYZ --secret-env WALLET_SK
```

`stellar-agent profile show default` requires an existing profile file and exits
`1` on a clean install. The synthesised in-memory testnet default is used only by
`stellar-agent-mcp` startup, not by `profile show`.

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

- [Documentation for users](docs/README.md#for-users) — getting started,
  concepts, the CLI and MCP references, protocols, toolsets, profiles, and
  remote approval.
- [Documentation for maintainers](docs/README.md#for-maintainers) —
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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

---

"Stellar" is a trademark of the Stellar Development Foundation.
This is an independent project, not affiliated with, sponsored or endorsed by the Stellar Development Foundation.
