# Documentation

Documentation for the Stellar Agent Wallet: a Stellar wallet for AI agents,
shipping a `stellar-agent` CLI and a `stellar-agent-mcp` MCP server.

## For users

- [What is the Stellar Agent Wallet?](onboarding.md) — the non-technical
  tour: what it is, what an agent can do with it, and how a first session
  with Claude Code looks. Start here.
- [Getting started](getting-started.md) — install, create a profile, fund a
  testnet account, and make a first payment.
- [Concepts](concepts.md) — the security and governance model: profiles, key
  custody, the policy engine, the approval spine, and the audit log.
- [CLI reference](cli-reference/index.md) — the `stellar-agent` command surface.
  - [Wallet (smart-account governance)](cli-reference/wallet.md)
  - [Accounts and core Stellar operations](cli-reference/stellar-ops.md)
  - [DeFi and the channel pool](cli-reference/defi-and-pool.md)
  - [Profiles, credentials, approvals, and audit](cli-reference/profile-and-governance.md)
- [The MCP server](mcp.md) — run the server and wire it into an MCP client.
- [Driving the wallet from an AI agent](agents.md) — connect an agent to the MCP
  server and the call patterns that keep funds safe.
- [Protocols and integrations](protocols.md) — the supported SEPs, x402, and DeFi
  venues.
- [Agent toolsets](toolsets.md) — packaging, signing, and running the wallet's
  capability-restricting toolsets.
- [Profile configuration](profiles.md) — the profile TOML reference and the
  key-rotation runbook.

The downloadable [agent knowledge skill](../skills/) (`skills/`) teaches an AI
agent how to operate the wallet without cloning the repository; it is distinct
from the capability-restriction toolsets feature above.

## For maintainers

- [Architecture](maintainers/architecture.md) — the crate map and dependency
  layering.
- [Building and testing](maintainers/building.md) — the build, the gate suite,
  and the test tiers.
- [Security internals](maintainers/security-internals.md) — the cryptographic
  detail behind the model.
- [Review checklist](maintainers/review-checklist.md) — the production-readiness
  gate every change passes.
