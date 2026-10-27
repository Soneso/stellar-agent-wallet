# Stability tiers

See [Mainnet configurations and scope](../getting-started.md#mainnet-configurations-and-scope)
for build configuration, admitted operations, and exclusions.

What each workspace crate is for, how settled its API is, and what a
deployer can rely on. Tiers express support intent and relative maturity.
They are not SemVer guarantees. Every crate is pre-1.0: any surface may
change between alpha releases, and the CHANGELOG records every change that
matters. What the tiers add is where change is likely, where it is avoided,
and where a report of breakage is treated as a bug rather than as expected
churn.

Facts that apply to every crate:

- Of the 37 workspace members, 36 are published on crates.io at the shared
  workspace version. Cargo requires every dependency of a published crate to
  be published, so internal crates are published too; their tier and
  description say what that does and does not mean.
- The unpublished `stellar-agent-smart-account-acceptance` member holds live
  acceptance suites only. It has no tier and no row in the Crates table.
- The mainnet column describes the scope of feature-enabled builds. Released
  binaries have the feature off. See
  [Mainnet configurations and scope](../getting-started.md#mainnet-configurations-and-scope).
- The `stellar-agent` and `stellar-agent-mcp` binaries bundle every surface
  during alpha. Cargo feature groups (`payments`, `smart-account`,
  `anchors`, `wallet-protocols`, `high-throughput`, `claimable-balances`)
  are intended for later; they are not implemented yet.

## Tier definitions

- **Level 1, stable core.** The agent-payment runtime. Strongest
  compatibility intent: breaking changes are avoided where possible, always
  called out with migration notes, and breakage reports are treated as
  bugs. Covered by the full acceptance gates on every release.
- **Level 2, supported optional.** Maintained and tested with the same
  gates, but the API may evolve before 1.0 with less ceremony. Protocol
  surfaces (SEPs), operational tooling, and the approval interfaces live
  here.
- **Level 3, experimental.** Best effort, testnet-first. APIs and formats
  may change without migration notes. Guaranteed maintenance of a Level 3
  surface requires sponsorship.
- **Internal.** Workspace machinery published only because crates.io
  requires it. No API stability promise of any kind; do not depend on these
  directly. Each carries this language in its crate description.
- **Removed.** Previously shipped, no longer part of the wallet. Published
  versions remain installable on crates.io; no new versions are published.

## Crates

| Crate | Tier | Surface | Mainnet posture |
|---|---|---|---|
| `stellar-agent-core` | 1 | profile, policy engine, audit chain, envelopes | supports admitted beta operations through policy and authorization proofs |
| `stellar-agent-network` | 1 | RPC client, submit, retry, keyring stores | supports admitted beta operations through authorized signing and submission |
| `stellar-agent-nonce` | 1 | replay protection for MCP tools | supports admitted beta operations through MCP replay protection |
| `stellar-agent-smart-account` | 1 | C-account deploy, rules, signers, submit | excluded from beta for writes; read or local only |
| `stellar-agent-cli` | 1 | the `stellar-agent` binary | supports admitted beta operations through the listed full-mode verbs |
| `stellar-agent-mcp` | 1 | the `stellar-agent-mcp` binary | supports admitted beta operations through the listed tools |
| `stellar-agent-x402` | 1 | x402 exact-payment scheme | supports admitted beta operations through authorized x402 payments |
| `stellar-agent-mpp` | 1 | machine-payable-page charge lifecycle | excluded from beta |
| `stellar-agent-x402-identity` | 2 | SEP-10 gate for authenticated x402 | supports admitted beta operations through authenticated x402 payments |
| `stellar-agent-stablecoin` | 2 | issuer registry, trustline verb (payments support) | supports admitted beta operations through trustline actions; issuer queries are read-only |
| `stellar-agent-pool` | 2 | channel-account pool | excluded from beta for submission; read or local only |
| `stellar-agent-claimable` | 2 | claimable balances | supports admitted beta operations through claim actions |
| `stellar-agent-anchor` | 2 | SEP-6 / SEP-24 anchor flows | read or local only; anchor flows grant no mainnet signing authority |
| `stellar-agent-sep5` | 2 | key derivation vectors | read or local only; key derivation grants no mainnet signing authority |
| `stellar-agent-sep7` | 2 | URI parsing | read or local only; URI parsing grants no mainnet signing authority |
| `stellar-agent-sep10` | 2 | web authentication | supports admitted beta operations only through bound x402 identity authentication |
| `stellar-agent-sep43` | 2 | wallet-interface signing | excluded from beta for public signing tools; its authorized primitive supports admitted x402 payments |
| `stellar-agent-sep45` | 2 | contract-account authentication | excluded from beta |
| `stellar-agent-sep48` | 2 | invocation preview | read or local only; invocation preview grants no signing authority |
| `stellar-agent-sep53` | 2 | message signing | excluded from beta for message signing; verification is read-only |
| `stellar-agent-approval-ui` | 2 | loopback approval pages and decision spine | supports admitted beta operations through supported classic approval attestations |
| `stellar-agent-approval-remote` | 2 | network-reachable approval listener | supports admitted beta operations through supported classic approval attestations |
| `stellar-agent-loopback-http` | 2 | loopback HTTP substrate for served pages | read or local only; HTTP transport grants no signing authority |
| `stellar-agent-webauthn-bridge` | 2 | local WebAuthn registration bridge | read or local only; registration grants no transaction authority |
| `stellar-agent-headless-keyring` | 2 | env-key keyring backend for headless hosts | supports admitted beta operations through its enrolled-key consumers |
| `stellar-agent-defi` | 3 | DeFi adapter substrate (pins, preview, dispatch) | excluded from beta |
| `stellar-agent-defindex` | 3 | DeFindex vault adapter | excluded from beta |
| `stellar-agent-dex` | 3 | Soroswap swap adapter | excluded from beta |
| `stellar-agent-toolsets` | 3 | toolset package format (no format-stability promise) | read or local only; toolset packages admit no mainnet signing |
| `stellar-agent-toolsets-install` | 3 | toolset install and attestation | read or local only; installation admits no mainnet signing |
| `stellar-agent-toolsets-runtime` | 3 | toolset invocation runtime | read or local only; signing actions refuse mainnet |
| `stellar-agent-mcp-macros` | internal | proc-macros for the MCP registry | supports admitted beta operations through its MCP registry consumers |
| `stellar-agent-soroban-auth` | internal | Soroban authorization preimages and signature payloads | supports admitted beta operations through its authorized Soroban consumers |
| `stellar-agent-test-support` | internal | test harness and fixtures | supports tests of admitted beta operations; grants no production authority |
| `stellar-agent-windows-identity` | internal | Win32 SID / DPAPI wrappers | supports admitted beta operations through its Windows identity consumers |
| `stellar-agent-xdr-limits` | internal | XDR decode bounds | supports admitted beta operations through its bounded XDR decoders |

"Supports admitted beta operations" limits support to the operations and
consumers listed in the scope table. Supporting infrastructure does not grant
authority by itself. "Excluded from beta" means the capability does not admit
that signing or write surface. "Read or local only" grants no transaction-write
authority. These descriptions do not change maturity tiers.

## Removed

- **`stellar-agent-blend` (Blend lending), removed in the v0.1.0-alpha.7
  cycle.** The lending verb depended on Blend's backstop for depositor
  protection; the August 2026 Comet pool exploit drained that backstop and
  the protocol's pools are winding down. Re-integration would require a
  published post-mortem, a backstop rebuilt on an audited AMM, and a fresh
  integration review of the rebuilt protocol. DeFindex's Blend-strategy
  disclosure is unrelated to the removed adapter and remains.

## External dependents

Verified 2026-09-02 against crates.io reverse dependencies: no crate in
this workspace has an external dependent (the only registered dependents
are workspace siblings). In particular `stellar-agent-approval-remote`,
the crate most likely to attract external integration, has none. Its API
may evolve under Level 2 rules without external coordination.

## Intent, not yet implemented

- Cargo feature groups for the binaries (see above).
- Facade crates: one public approval API over the approval crates, a
  toolsets umbrella, a SEP umbrella. Recorded here so the current many-crate
  surface is understood as layout, not as 36 independent commitments.
