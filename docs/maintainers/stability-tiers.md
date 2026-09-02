# Stability tiers

What each workspace crate is for, how settled its API is, and what a
deployer can rely on. Tiers express support intent and relative maturity —
they are not SemVer guarantees. Every crate is pre-1.0: any surface may
change between alpha releases, and the CHANGELOG records every change that
matters. What the tiers add is where change is likely, where it is avoided,
and where a report of breakage is treated as a bug rather than as expected
churn.

Facts that apply to every crate:

- All 35 crates are published on crates.io at the shared workspace version.
  Cargo requires every dependency of a published crate to be published, so
  internal crates are published too; their tier and description say what
  that does and does not mean.
- Mainnet writes are structurally refused by every surface today, at the
  network layer. The mainnet column below records the intended posture once
  the constrained-mainnet capability ships, not present behavior.
- The `stellar-agent` and `stellar-agent-mcp` binaries bundle every surface
  during alpha. Cargo feature groups (`payments`, `smart-account`,
  `anchors`, `wallet-protocols`, `high-throughput`, `claimable-balances`)
  are intended for later; they are not implemented yet.

## Tier definitions

- **Level 1 — stable core.** The agent-payment runtime. Strongest
  compatibility intent: breaking changes are avoided where possible, always
  called out with migration notes, and breakage reports are treated as
  bugs. Covered by the full acceptance gates on every release.
- **Level 2 — supported optional.** Maintained and tested with the same
  gates, but the API may evolve before 1.0 with less ceremony. Protocol
  surfaces (SEPs), operational tooling, and the approval interfaces live
  here.
- **Level 3 — experimental.** Best effort, testnet-first. APIs and formats
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
| `stellar-agent-core` | 1 | profile, policy engine, audit chain, envelopes | pending capability |
| `stellar-agent-network` | 1 | RPC client, submit, retry, keyring stores | pending capability |
| `stellar-agent-nonce` | 1 | replay protection for MCP tools | pending capability |
| `stellar-agent-smart-account` | 1 | C-account deploy, rules, signers, submit | pending capability |
| `stellar-agent-cli` | 1 | the `stellar-agent` binary | pending capability |
| `stellar-agent-mcp` | 1 | the `stellar-agent-mcp` binary | pending capability |
| `stellar-agent-x402` | 1 | x402 exact-payment scheme | pending capability |
| `stellar-agent-mpp` | 1 | machine-payable-page charge lifecycle | pending capability |
| `stellar-agent-x402-identity` | 2 | SEP-10 gate for authenticated x402 | pending capability |
| `stellar-agent-stablecoin` | 2 | issuer registry, trustline verb (payments support) | pending capability |
| `stellar-agent-pool` | 2 | channel-account pool | pending capability |
| `stellar-agent-claimable` | 2 | claimable balances | pending capability |
| `stellar-agent-anchor` | 2 | SEP-6 / SEP-24 anchor flows | pending capability |
| `stellar-agent-sep5` | 2 | key derivation vectors | n/a |
| `stellar-agent-sep7` | 2 | URI parsing | n/a |
| `stellar-agent-sep10` | 2 | web authentication | pending capability |
| `stellar-agent-sep43` | 2 | wallet-interface signing | pending capability |
| `stellar-agent-sep45` | 2 | contract-account authentication | pending capability |
| `stellar-agent-sep48` | 2 | invocation preview | n/a (read-only) |
| `stellar-agent-sep53` | 2 | message signing | pending capability |
| `stellar-agent-approval-ui` | 2 | loopback approval pages and decision spine | pending capability |
| `stellar-agent-approval-remote` | 2 | network-reachable approval listener | pending capability |
| `stellar-agent-loopback-http` | 2 | loopback HTTP substrate for served pages | n/a |
| `stellar-agent-webauthn-bridge` | 2 | local WebAuthn registration bridge | n/a |
| `stellar-agent-headless-keyring` | 2 | env-key keyring backend for headless hosts | pending capability |
| `stellar-agent-defi` | 3 | DeFi adapter substrate (pins, preview, dispatch) | testnet-first |
| `stellar-agent-defindex` | 3 | DeFindex vault adapter | testnet-first |
| `stellar-agent-dex` | 3 | Soroswap swap adapter | testnet-first |
| `stellar-agent-toolsets` | 3 | toolset package format (no format-stability promise) | testnet-first |
| `stellar-agent-toolsets-install` | 3 | toolset install and attestation | testnet-first |
| `stellar-agent-toolsets-runtime` | 3 | toolset invocation runtime | testnet-first |
| `stellar-agent-mcp-macros` | internal | proc-macros for the MCP registry | n/a |
| `stellar-agent-test-support` | internal | test harness and fixtures | n/a |
| `stellar-agent-windows-identity` | internal | Win32 SID / DPAPI wrappers | n/a |
| `stellar-agent-xdr-limits` | internal | XDR decode bounds | n/a |

"Pending capability" means the surface participates in signing or
submission and will sit behind the constrained-mainnet capability gate when
it ships; until then it operates on testnet, and mainnet writes are refused
structurally. "Testnet-first" means the surface has no committed mainnet
plan; Level 3 surfaces are excluded from the initial mainnet-write
allowlist regardless.

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
the crate most likely to attract external integration, has none — its API
may evolve under Level 2 rules without external coordination.

## Intent, not yet implemented

- Cargo feature groups for the binaries (see above).
- Facade crates: one public approval API over the approval crates, a
  toolsets umbrella, a SEP umbrella. Recorded here so the current many-crate
  surface is understood as layout, not as 35 independent commitments.
